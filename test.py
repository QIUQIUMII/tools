#coding = 'utf-8'
import os
import subprocess
import time
import json
from xml.dom.minidom import Element
from xml.dom import  minidom
from lxml import etree
from concurrent.futures import ThreadPoolExecutor

import openpyxl  # pip install openpyxl
from androguard.core.apk import APK

class APKAnalyzer:
    """
    使用Androguard解析APK，获取以下信息：
      - 应用包名
      - 所有 <activity> 标签的详细信息：
         * activityName (全限定名)
         * android:exported 显式设置值（true/false/空字符串）
         * android:permission（若有）
         * intent-filters 列表，每个intent-filter包含:
            - actions
            - categories
            - data(可能含scheme、host、port、path等)
    """

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.package_name = None

    def analyze(self):
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
        apk = APK(self.apk_path)
        self.package_name = apk.get_package()
        manifest_xml = apk.get_android_manifest_xml()
        # manifest_xml_str = apk.get_android_manifest_xml()
        # print(type(manifest_xml_str)) #<class 'lxml.etree._Element'>
        # manifest_xml = minidom.parseString(manifest_xml_str)

        #将<class 'lxml.etree._Element'>转换成minidom
        manifest_xml = minidom.parseString(etree.tostring(manifest_xml, encoding="unicode"))
        print(manifest_xml.toprettyxml(indent=""))
        activities_info = []
        activity_elements = manifest_xml.getElementsByTagName("activity")

        for activity in activity_elements:
            # 1) 获取 activityName(可能是相对路径，也可能是绝对路径)
            raw_name = activity.getAttribute("android:name")
            full_name = self._normalize_activity_name(raw_name, self.package_name)

            # 2) 获取 exported / permission
            exported_val = activity.getAttribute("android:exported").lower().strip()
            permission_val = activity.getAttribute("android:permission").strip()
            if not permission_val:
                permission_val = None  # 便于后续判断

            # 3) 获取所有 intent-filter
            intent_filters = self._parse_intent_filters(activity)

            activity_info = {
                "activityName": full_name,
                "exported": exported_val,
                "permission": permission_val,
                "intent_filters": intent_filters
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


class ActivityInspector:
    """
    根据解析结果判断哪些 Activity 是“攻击面”。
    规则示例：若 exported=true，或（exported 未设置 且 存在intent-filter），则认为可能是攻击面。
    (permission 字段本示例仅记录，不纳入攻击面判断。)
    """
    @staticmethod
    def is_attack_surface(activity_info):
        exported_val = activity_info["exported"]
        intent_filters = activity_info["intent_filters"]

        # 若显式设置 android:exported="true"
        if exported_val == "true":
            return True
        # 若显式设置 android:exported="false"
        if exported_val == "false":
            return False
        # 若既没设置 exported，又存在 intent-filter，则可能是隐式导出
        if exported_val == "" and len(intent_filters) > 0:
            return True
        return False


class ExcelReporter:
    """
    将结果输出到 Excel 文件，包含两个工作表：
      1) Activity_Analysis：每个 Activity 详细信息（是否攻击面）
      2) AttackSurfaceTest：对攻击面 Activity 做测试时的 Intent 及结果
    """

    def __init__(self, output_xlsx):
        self.output_xlsx = output_xlsx
        # 创建工作簿与工作表
        self.wb = openpyxl.Workbook()
        # 第一个表：记录 Activity 详情
        self.ws_analysis = self.wb.active
        self.ws_analysis.title = "Activity_Analysis"

        # 第二个表：记录测试情况
        self.ws_test = self.wb.create_sheet("AttackSurfaceTest")

        # 初始化表头
        self._init_sheets()

    def _init_sheets(self):
        # Activity_Analysis
        headers_analysis = [
            "ActivityName",
            "Exported(Raw)",
            "Permission",
            "IntentFilterCount",
            "IsAttackSurface",
            "IntentFilters(JSON)"
        ]
        self.ws_analysis.append(headers_analysis)

        # AttackSurfaceTest
        headers_test = [
            "ActivityName",
            "FilterIndex",
            "Actions",
            "Categories",
            "DataAttrs(JSON)",
            "ConstructedIntent",
            "TestResult"
        ]
        self.ws_test.append(headers_test)

    def write_analysis(self, activities_info):
        """
        将所有 Activity 信息写入 'Activity_Analysis' 表。
        其中 'IsAttackSurface' 列通过 ActivityInspector 判定。
        """
        for activity_info in activities_info:
            is_attack = ActivityInspector.is_attack_surface(activity_info)
            row_data = [
                activity_info["activityName"],
                activity_info["exported"] if activity_info["exported"] else "",
                activity_info["permission"] if activity_info["permission"] else "",
                len(activity_info["intent_filters"]),
                str(is_attack),
                json.dumps(activity_info["intent_filters"], ensure_ascii=False)
            ]
            self.ws_analysis.append(row_data)

    def write_test_result(self, test_results):
        """
        将测试结果写入 'AttackSurfaceTest' 表。
        test_results 中的每一条记录格式：
        {
          "activityName": ...,
          "filterIndex": int,
          "actions": [...],
          "categories": [...],
          "dataAttrs": { ... },
          "constructedIntent": <str>,
          "testResult": <str>
        }
        """
        for item in test_results:
            row_data = [
                item["activityName"],
                item["filterIndex"],
                ", ".join(item["actions"]) if item["actions"] else "",
                ", ".join(item["categories"]) if item["categories"] else "",
                json.dumps(item["dataAttrs"], ensure_ascii=False),
                item["constructedIntent"],
                item["testResult"]
            ]
            self.ws_test.append(row_data)

    def save(self):
        self.wb.save(self.output_xlsx)


class IntentBuilder:
    """
    根据 Activity 的 intent-filter 构造 Intent 命令示例。
    每个 Activity 可能有多个 intent-filter，每个 filter 可能有多个 actions/categories/datas。
    示例中我们仅选用 '第一个 action' + '全部 category' + '每个 data组合' 去构造 Intent，
    并添加多种变体（data 传递URL、extra 传递URL等）。
    你可以根据需要自由扩展。
    """
    def __init__(self, package_name, target_url):
        self.package_name = package_name
        self.target_url = target_url

    def build_intents_for_activity(self, activity_info):
        """
        若是攻击面，针对其每个 intent-filter 生成多条命令。
        返回列表，其中每条是 dict：
        {
           "activityName": ...,
           "filterIndex": int,
           "actions": [...],
           "categories": [...],
           "dataAttrs": { ... },
           "constructedIntent": <str>
        }
        """
        is_attack = ActivityInspector.is_attack_surface(activity_info)
        if not is_attack:
            return []  # 非攻击面就不构造任何命令

        results = []
        filters = activity_info["intent_filters"]
        for idx, f in enumerate(filters):
            # 根据第一个action + 全部category + 每个data进行组合
            actions = f["actions"]
            categories = f["categories"]
            datas = f["datas"]

            # 如果没有 actions，则可能只能显式启动
            # 这里也可以考虑：若无 actions 就填 ACTION_VIEW 等默认值
            if not actions:
                # 直接构造一个显式启动的指令即可
                actions = [""]  # 用空串代表无 action

            for data_index, data_attrs in enumerate(datas):
                # 先获取第一个action(示例只用第一个)
                action_to_use = actions[0] if actions else None
                # 构造基本 cmd
                component = f"{self.package_name}/{activity_info['activityName']}"
                base_cmd = f"adb shell am start -n {component}"

                if action_to_use:
                    base_cmd += f" -a {action_to_use}"

                # 添加 category
                for cat in categories:
                    base_cmd += f" -c {cat}"

                # 然后演示多种 URL 传递方式 (此处和之前思路相似):
                # 1. data 传 URL
                # 2. extra 传 URL
                # 3. json 封装
                # 4. data+extra 组合

                constructed_cmds = []

                # (A) data 直接传递 URL
                cmd_a = base_cmd + f' -d "{self.target_url}"'
                constructed_cmds.append(cmd_a)

                # (B) extra 传递 URL
                cmd_b = base_cmd + f' -e url "{self.target_url}"'
                constructed_cmds.append(cmd_b)

                # (C) JSON 封装后放 extra
                json_payload = json.dumps({"url": self.target_url})
                cmd_c = base_cmd + f" -e json '{json_payload}'"
                constructed_cmds.append(cmd_c)

                # (D) data + extra 组合
                cmd_d = base_cmd + f' -d "{self.target_url}" -e target "{self.target_url}"'
                constructed_cmds.append(cmd_d)

                for c in constructed_cmds:
                    results.append({
                        "activityName": activity_info["activityName"],
                        "filterIndex": idx,
                        "actions": f["actions"],     # 记录下来便于查看
                        "categories": f["categories"],
                        "dataAttrs": data_attrs,
                        "constructedIntent": c
                    })
        return results


class IntentTester:
    """
    通过 ADB 发送上面构造的 Intent，并记录执行结果。
    """

    def __init__(self, interval=2, concurrency=1):
        self.interval = interval
        self.concurrency = concurrency

    def test_intents(self, all_intent_cmds):
        """
        批量测试所有构造的命令，控制并发和发送间隔。
        all_intent_cmds 是一个列表，列表元素为:
        {
          "activityName": ...,
          "filterIndex": ...,
          "actions": ...,
          "categories": ...,
          "dataAttrs": ...,
          "constructedIntent": ...
        }
        最终返回包含 testResult 的结构同上，但多一项 "testResult"
        """
        results = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_map = {}
            for i, item in enumerate(all_intent_cmds):
                # 间隔
                if i != 0:
                    time.sleep(self.interval)

                cmd = item["constructedIntent"]
                future = executor.submit(self._run_adb_command, cmd)
                future_map[future] = item

            for future in future_map:
                item = future_map[future]
                success, output = future.result()

                ret_item = item.copy()
                if success:
                    # 可能只是表示ADB命令执行成功，并不代表一定加载URL
                    # 需要人工查看日志，这里暂记为 "Pending"
                    ret_item["testResult"] = "Pending"
                else:
                    ret_item["testResult"] = f"Failed: {output}"

                results.append(ret_item)

        return results

    def _run_adb_command(self, cmd):
        """
        执行单条 adb shell am start 命令, 返回 (success, output)
        """
        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            out = proc.stdout + proc.stderr
            if proc.returncode != 0:
                return False, out
            # 若输出中包含异常信息也视为失败
            if "Exception" in out or "Error" in out:
                return False, out
            return True, out
        except Exception as e:
            return False, str(e)


def main(apk_path, output_xlsx, target_url, concurrency=1, interval=2):
    # 1. 分析 APK
    analyzer = APKAnalyzer(apk_path)
    activities_info = analyzer.analyze()

    if not activities_info:
        print("[!] 未从 APK 中解析到任何 Activity 信息。")
        return

    print(f"[*] 已分析完毕，发现 {len(activities_info)} 个 Activity。")

    # 2. 将所有 Activity 信息写入 Excel（Activity_Analysis）
    reporter = ExcelReporter(output_xlsx)
    reporter.write_analysis(activities_info)

    # 3. 筛选攻击面，并针对其构造 Intent
    builder = IntentBuilder(analyzer.package_name, target_url)
    all_test_intents = []
    for act_info in activities_info:
        test_cmds = builder.build_intents_for_activity(act_info)
        all_test_intents.extend(test_cmds)

    if not all_test_intents:
        print("[*] 未发现任何可疑攻击面，无需发送 Intent 测试。")
        reporter.save()
        return

    print(f"[*] 有 {len(all_test_intents)} 条 Intent 需要测试(针对可能的攻击面)。")

    # 4. 批量测试
    tester = IntentTester(interval=interval, concurrency=concurrency)
    test_results = tester.test_intents(all_test_intents)

    # 5. 将测试结果写入 Excel（AttackSurfaceTest）
    reporter.write_test_result(test_results)
    reporter.save()
    print(f"[+] 测试完成，结果已写入 {output_xlsx}。请人工查看日志确认是否真正加载了 URL。")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="自动化测试：检测 APK 是否存在可能的 WebView 任意 URL 加载攻击面")
    parser.add_argument("-apk", help="待分析的APK文件路径")
    parser.add_argument("-o", "--output", default="analysis_result.xlsx", help="输出Excel文件")
    parser.add_argument("-u", "--url", default="https://mymalware.com", help="测试时使用的URL")
    parser.add_argument("-c", "--concurrency", type=int, default=1, help="并发线程数")
    parser.add_argument("-i", "--interval", type=int, default=2, help="每条Intent发送间隔(秒)")
    args = parser.parse_args()

    # 运行主流程
    if not os.path.isfile(args.apk):
        print(f"[!] 指定的 APK 文件不存在: {args.apk}")
        exit(1)

    main(
        apk_path=args.apk,
        output_xlsx=args.output,
        target_url=args.url,
        concurrency=args.concurrency,
        interval=args.interval
    )
