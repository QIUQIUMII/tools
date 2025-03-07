#coding = 'utf-8'
import os
import subprocess
import time
import json
from xml.dom.minidom import Element
from xml.dom import  minidom

from gitdb.util import mkdir
from lxml import etree
from concurrent.futures import ThreadPoolExecutor
import openpyxl  # pip install openpyxl
# from androguard.core.apk import APK
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
import sqlite3

class AppAnalyzer:
    def __init__(self, apk_path):
        """
        初始化
        :param apk_path: 代分析的apk的路径
        """

        # 加载并解析 APK 文件，a 为 APK 对象，d 为 DalvikVMFormat 对象，dx 为 Analysis 对象
        self.apk, self.d, self.dx = AnalyzeAPK(apk_path)
        self.apk_path = apk_path
        self.package_name = self.apk.get_package()
        manifest_xml = self.apk.get_android_manifest_xml()
        self.manifest_xml = minidom.parseString(etree.tostring(manifest_xml, encoding="unicode"))

    def analyze_activities(self):
        """
        返回一个包含所有Activity信息的列表。
        每个元素形如：
        {
          "activityName": <str>,
          "exported": <"true"|"false"|""(未显式)>,
          "permission": <str或None>,
          "intent_filters": [
              {
                  "actions": [...],
                  "categories": [...],
                  "datas": [ {scheme=xx,host=xx,...} ... ]
              },
              ...
          ]
        }
        """
        activities_info = []
        activity_elements = self.manifest_xml.getElementsByTagName("activity")

        for activity_element in activity_elements:
            # 1) 获取 activityName(可能是相对路径，也可能是绝对路径)
            raw_name = activity_element.getAttribute("android:name")
            full_name = self._normalize_activity_name(raw_name, self.package_name)

            # 2) 获取 exported
            exported_val = activity_element.getAttribute("android:exported").lower().strip()

            # 3) 获取 permission
            permission_val = activity_element.getAttribute("android:permission").strip()

            # 4) 获取所有 intent-filter
            intent_filters = self._parse_intent_filters(activity_element)

            # 整合activity信息
            activity_info = {
                "activityName": full_name,
                "exported": exported_val if exported_val else None,
                "permission": permission_val if permission_val else None,
                "intent_filters": intent_filters if intent_filters else None,
            }
            activities_info.append(activity_info)

        return activities_info

    def _normalize_activity_name(self, raw_name, package_name):
        """
        将可能是 .MainActivity 等相对路径的 Activity 名称转换成全限定类名
        """
        if raw_name.startswith("."):
            return package_name + raw_name
        elif "." not in raw_name:
            # 不包含 '.' 则视为相对路径
            return f"{package_name}.{raw_name}"
        else:
            # 已经是绝对路径
            return raw_name

    def _parse_intent_filters(self, activity_element: Element):
        """
        解析 <activity> 下的 <intent-filter> 信息。
        每个 intent-filter 返回结构：
        {
          "actions": [...],
          "categories": [...],
          "datas": [
             {
                "scheme": <str或None>,
                "host": <str或None>,
                "port": <str或None>,
                "path": <str或None>,
                "pathPrefix": <str或None>,
                "pathPattern": <str或None>,
                "mimeType": <str或None>
             }, ...
          ]
        }
        """
        result = []
        intent_filters = activity_element.getElementsByTagName("intent-filter")
        for f in intent_filters:
            # 1) 收集 actions
            action_list = []
            for act in f.getElementsByTagName("action"):
                action_name = act.getAttribute("android:name")
                if action_name:
                    action_list.append(action_name)

            # 2) 收集 categories
            category_list = []
            for cat in f.getElementsByTagName("category"):
                cat_name = cat.getAttribute("android:name")
                if cat_name:
                    category_list.append(cat_name)

            # 3) 收集 data
            data_list = []
            for d in f.getElementsByTagName("data"):
                data_attrs = {
                    "scheme": d.getAttribute("android:scheme") or None,
                    "host": d.getAttribute("android:host") or None,
                    "port": d.getAttribute("android:port") or None,
                    "path": d.getAttribute("android:path") or None,
                    "pathPrefix": d.getAttribute("android:pathPrefix") or None,
                    "pathPattern": d.getAttribute("android:pathPattern") or None,
                    "mimeType": d.getAttribute("android:mimeType") or None
                }
                data_list.append(data_attrs)

            # 若没有 <data> 标签，也加一个空数据，以便后续构造 Intent 时考虑
            if not data_list:
                data_list.append({
                    "scheme": None,
                    "host": None,
                    "port": None,
                    "path": None,
                    "pathPrefix": None,
                    "pathPattern": None,
                    "mimeType": None
                })

            filter_obj = {
                "actions": action_list,
                "categories": category_list,
                "datas": data_list
            }
            result.append(filter_obj)

        return result

    def store_activities_in_db(self):
        """
        执行 analyze_activities() 并且将结果存入数据库。
        表：activity_info
        列：(package_name, activity_name, exported, permission, intent_filters)
        键：(package_name, activity_name)
        若表不存在就创建；
        若有重复键则替换（INSERT OR REPLACE）。
        """
        db_path = './all.db'

        # 获取所有 Activity 信息
        activities_info = self.analyze_activities()

        # 连接数据库，不存在则会自动创建
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 创建表（如果不存在）
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS activity_info (
            package_name   TEXT NOT NULL,
            activity_name  TEXT NOT NULL,
            exported       TEXT,
            permission     TEXT,
            intent_filters TEXT,
            PRIMARY KEY (package_name, activity_name)
        )
        """
        cursor.execute(create_table_sql)

        # 插入或替换数据
        insert_sql = """
        INSERT OR REPLACE INTO activity_info 
            (package_name, activity_name, exported, permission, intent_filters)
        VALUES 
            (?, ?, ?, ?, ?)
        """

        for activity in activities_info:
            # 将 intent_filters 转成 JSON 字符串存储
            # 如果你不需要存储 intent_filters，可以去掉
            intent_filters_json = json.dumps(activity["intent_filters"]) if activity["intent_filters"] else None

            cursor.execute(insert_sql, (
                self.package_name,
                activity["activityName"],
                activity["exported"],
                activity["permission"],
                intent_filters_json
            ))

        # 提交更改并关闭连接
        conn.commit()
        conn.close()

class AttackSurfaceInspector:
    """
    从all.db中获取相关数据后分析。并插入分析结果。
    """
    def __init__(self, package_name):
        self.db_path = './all.db'
        self.package_name = package_name

    def activity_inspector(self):
        '''
        从 activity_info 表中读取 self.package_name 的 activity 信息。然后分析各个活动是否是攻击面。
        1. 在 activity_info 中的列 is_attack_surface (如果不存在则新建此列)记录分析结果。
        2. 在 activity_info 中的列 prot_level (如果不存在则新建此列)记录所使用的权限级别。
        3. 在 activity_info 中的列 used_free_permission (如果不存在则新建此列)记录是否使用了游离权限。

        如果一个 activity 满足下面所有条件，则它是攻击面（第三方普通应用无条件调用该 Activity）：
            1. android:exported="true"（明确允许导出。在 Android 12+ 中，如果存在 <intent-filter> ，则必须显式声明是否导出。所以这里不再考虑未设置 exported 属性的隐式调用情况）
            2. 权限设置允许调用：要么没有设置 android:permission，要么设置的权限是普通（normal）级别，要么设置的权限不存在（游离权限）
        '''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 检查并新增所需列（如果不存在）
        self._insert_column(conn, "activity_info", ["is_attack_surface", "prot_level", "used_free_permission"])

        # 读取当前 package 下的所有 activity 信息
        select_sql = """
        SELECT package_name, activity_name, exported, permission 
        FROM activity_info 
        WHERE package_name = ?
        """
        cursor.execute(select_sql, (self.package_name,))
        rows = cursor.fetchall()

        for row in rows:
            package_name, activity_name, exported, permission = row

            # 默认分析结果
            is_attack_surface = "false"
            prot_level_result = None
            used_free_permission = "false"

            # 获取该权限的保护级别
            perm_level = self._check_permission(permission)

            # 判断条件1：必须明确导出
            if exported is not None and exported.lower() == "true":
                # 判断条件2：权限允许调用
                if permission is None or permission.strip() == "":
                    # 未设置权限，允许调用
                    is_attack_surface = "true"
                    used_free_permission = "false"

                else:
                    if perm_level is None:
                        # 权限未在 permission_info 中找到，视为游离权限
                        is_attack_surface = "true"
                        used_free_permission = "true"
                    elif "normal" in perm_level.lower():
                        is_attack_surface = "true"
                        prot_level_result = perm_level
                    else:
                        # 权限保护级别不为 normal ，则不允许第三方调用
                        prot_level_result = perm_level
            else:
                prot_level_result = self._check_permission(permission)


            # 更新数据库中对应的记录
            update_sql = """
            UPDATE activity_info
            SET is_attack_surface = ?,
                prot_level = ?,
                used_free_permission = ?
            WHERE package_name = ? AND activity_name = ?
            """
            cursor.execute(update_sql, (
                is_attack_surface,
                prot_level_result,
                used_free_permission,
                package_name,
                activity_name
            ))

        conn.commit()
        conn.close()

    def _insert_column(self, conn, table_name, column_names, column_type="TEXT"):
        """
        检查 table_name 表是否存在 column 列，
        若不存在则通过 ALTER TABLE 添加。
        """
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info{table_name}")
        existing_columns = [row[1] for row in cursor.fetchall()]  # row[1] 是列名
        for column_name in column_names:
            if column_name not in existing_columns:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        conn.commit()

    def _check_permission(self, permission_name):
        """
        从 permission_info 表中读取 permission_name 对应的 prot_level 信息。
        :param permission_name: 权限名称
        :return: 返回权限保护级别字符串，如果未找到则返回 None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT prot_level FROM permission_info WHERE permission_name = ?",
                (permission_name,)
            )
            result = cursor.fetchone()
            prot_level = result[0] if result else None
        except sqlite3.Error as e:
            prot_level = None
        conn.close()
        return prot_level


if __name__ == "__main__":
    analyzer = AppAnalyzer('./base.apk')
    analyzer.store_activities_in_db()
