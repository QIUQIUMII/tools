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
        self.package_name = self.apk.getPackageName()
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
        db_path = './apk_info.db'

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
