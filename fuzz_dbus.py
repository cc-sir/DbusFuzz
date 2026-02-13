#!/usr/bin/env python3
"""
DBus 接口 Fuzz 工具
实时枚举 DBus 接口并测试命令注入漏洞
测试目标: 执行 dde-calendar 命令

!!! 警告: 此工具仅用于授权的安全测试 !!!

用法:
    python3 fuzz_dbus.py                    # 实时枚举并 fuzz 所有接口
    python3 fuzz_dbus.py --bus system       # 测试系统总线
    python3 fuzz_dbus.py --filter deepin    # 只测试包含 deepin 的服务
"""

import dbus
import json
import sys
import time
import argparse
import subprocess
import xml.etree.ElementTree as ET
import uuid
from typing import List, Dict, Any


# 检测 dde-calendar 是否正在运行
def is_calendar_running():
    """检查 dde-calendar 进程是否存在"""
    try:
        result = subprocess.run(['pgrep', '-f', 'dde-calendar'],
                              capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False


# 生成随机 GUID 作为 payload
def generate_guid_payload():
    """生成随机 GUID 作为测试 payload"""
    return "xxxxx_" + str(uuid.uuid4())


def parse_introspect_xml(xml_data: str) -> Dict:
    """解析 Introspect XML，提取接口和方法信息"""
    result = {
        'interfaces': {}
    }

    try:
        root = ET.fromstring(xml_data)

        for interface in root.findall('interface'):
            iface_name = interface.get('name')
            if not iface_name or iface_name.startswith('org.freedesktop.DBus.'):
                continue

            methods = []
            for method in interface.findall('method'):
                method_name = method.get('name')
                input_params = []
                output_params = []

                for arg in method.findall('arg'):
                    param_info = {
                        'name': arg.get('name', '?'),
                        'type': arg.get('type', '')
                    }
                    if arg.get('direction', 'in') == 'in':
                        input_params.append(param_info)
                    else:
                        output_params.append(param_info)

                methods.append({
                    'name': method_name,
                    'input_params': input_params,
                    'output_params': output_params
                })

            if methods:
                result['interfaces'][iface_name] = methods

    except Exception as e:
        pass

    return result


def get_dbus_objects(bus, service: str, path: str = '/') -> List[str]:
    """递归获取服务的所有对象路径"""
    objects = []

    try:
        obj = bus.get_object(service, path)
        introspectable = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
        xml = introspectable.Introspect()

        root = ET.fromstring(xml)

        for child in root:
            if child.tag == 'node':
                node_name = child.get('name')
                if node_name:
                    if node_name.startswith('/'):
                        new_path = node_name
                    else:
                        new_path = path + '/' + node_name if not path.endswith('/') else path + node_name

                    objects.append(new_path)
                    # 递归获取子节点
                    objects.extend(get_dbus_objects(bus, service, new_path))

    except:
        pass

    return objects


def enumerate_dbus_interfaces(bus_type='session', filter_name=None):
    """实时枚举 DBus 接口"""
    print(f"[*] 正在枚举 {bus_type} 总线...")

    try:
        if bus_type == 'system':
            bus = dbus.SystemBus()
        else:
            bus = dbus.SessionBus()
    except Exception as e:
        print(f"[!] 无法连接到 {bus_type} 总线: {e}")
        return []

    # 获取所有服务名称
    try:
        dbus_obj = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        dbus_iface = dbus.Interface(dbus_obj, 'org.freedesktop.DBus')
        services = dbus_iface.ListNames()
    except Exception as e:
        print(f"[!] 无法获取服务列表: {e}")
        return []

    targets = []
    service_count = 0

    for service in services:
        # 跳过唯一名称（除非指定了过滤器）
        if service.startswith(':') and not filter_name:
            continue

        # 应用过滤器
        if filter_name and filter_name.lower() not in service.lower():
            continue

        service_count += 1
        print(f"    扫描服务: {service} ({service_count})", end='\r')

        try:
            # 获取根对象
            obj = bus.get_object(service, '/')
            introspectable = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
            xml = introspectable.Introspect()

            # 解析接口
            parsed = parse_introspect_xml(xml)

            # 获取所有对象路径
            paths = ['/']
            try:
                paths.extend(get_dbus_objects(bus, service, '/'))
            except:
                pass

            for path in paths:
                try:
                    obj = bus.get_object(service, path)
                    introspectable = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
                    xml = introspectable.Introspect()
                    parsed = parse_introspect_xml(xml)

                    for iface_name, methods in parsed['interfaces'].items():
                        # 只保留有字符串参数的方法
                        fuzzable_methods = []
                        for method in methods:
                            for param in method.get('input_params', []):
                                if param.get('type') in ['s', 'as']:
                                    fuzzable_methods.append(method)
                                    break

                        if fuzzable_methods:
                            targets.append({
                                'service': service,
                                'path': path,
                                'interface': iface_name,
                                'methods': fuzzable_methods
                            })
                except:
                    pass

        except Exception as e:
            pass

    print(f"\n[*] 发现 {len(targets)} 个可 fuzz 的目标")
    return targets


class DBusFuzzer:
    def __init__(self, check_result=True, delay=0.1):
        self.check_result = check_result
        self.delay = delay
        self.results = []
        self.total_calls = 0
        self.success_calls = 0
        self.error_calls = 0

    def build_default_args(self, input_params: List[Dict], fuzz_index: int, fuzz_value: str) -> tuple:
        """构建调用参数"""
        args = []
        can_build = True

        for i, param in enumerate(input_params):
            ptype = param.get('type', '')

            # 检查是否是复杂类型
            if ptype.startswith('a(') or ptype.startswith('(') or ptype == 'v':
                can_build = False
                break

            if i == fuzz_index:
                # 这是我们要 fuzz 的参数
                if ptype == 's':
                    args.append(fuzz_value)
                elif ptype == 'as':
                    args.append([fuzz_value])
                else:
                    can_build = False
                    break
            else:
                # 其他参数用默认值
                if ptype == 's':
                    args.append('')
                elif ptype == 'as':
                    args.append([''])
                elif ptype in ['i', 'n', 'q']:
                    args.append(0)
                elif ptype in ['u', 't']:
                    args.append(0)
                elif ptype == 'b':
                    args.append(False)
                elif ptype in ['d', 'x']:
                    args.append(0.0)
                elif ptype == 'o':
                    args.append('/')
                elif ptype == 'g':
                    args.append('')
                elif ptype == 'y':
                    args.append(0)
                elif ptype == 'ay':
                    args.append([0])
                elif ptype == 'ab':
                    args.append([False])
                elif ptype == 'ai':
                    args.append([0])
                elif ptype == 'au':
                    args.append([0])
                elif ptype == 'ad':
                    args.append([0.0])
                elif ptype == 'ao':
                    args.append(['/'])
                else:
                    can_build = False
                    break

        return (can_build, args) if can_build else (False, None)

    def fuzz_method(self, bus, service: str, path: str, interface: str, method: Dict):
        """Fuzz 单个方法"""
        method_name = method['name']
        input_params = method.get('input_params', [])

        # 找出所有字符串参数的位置
        string_param_indices = []
        for i, param in enumerate(input_params):
            if param.get('type') in ['s', 'as']:
                string_param_indices.append((i, param.get('type')))

        if not string_param_indices:
            return []

        results = []

        for param_idx, param_type in string_param_indices:
            # 每次测试使用一个新的随机 GUID
            payload = generate_guid_payload()
            self.total_calls += 1

            can_build, args = self.build_default_args(input_params, param_idx, payload)

            if not can_build:
                continue

            try:
                before = is_calendar_running() if self.check_result else False

                obj = bus.get_object(service, path)
                iface = dbus.Interface(obj, interface)
                method_func = getattr(iface, method_name)

                result = method_func(*args, timeout=2000)

                time.sleep(self.delay)

                after = is_calendar_running() if self.check_result else False

                self.success_calls += 1

                call_result = {
                    'service': service,
                    'path': path,
                    'interface': interface,
                    'method': method_name,
                    'payload': payload,
                    'param_index': param_idx,
                    'param_type': param_type,
                    'status': 'called',
                    'exec_detected': (not before and after) if self.check_result else False
                }

                results.append(call_result)

                if call_result['exec_detected']:
                    print(f"\n[!] 可能检测到命令执行!")
                    print(f"    服务: {service}")
                    print(f"    路径: {path}")
                    print(f"    接口: {interface}")
                    print(f"    方法: {method_name}")
                    print(f"    Payload: {payload}")

            except dbus.exceptions.DBusException as e:
                self.error_calls += 1
            except Exception as e:
                self.error_calls += 1

        return results

    def fuzz_target(self, bus, target: Dict):
        """Fuzz 单个目标"""
        service = target['service']
        path = target['path']
        interface = target['interface']
        methods = target['methods']

        print(f"\n[*] Fuzz: {service} {path}")
        print(f"    接口: {interface}")
        print(f"    方法数: {len(methods)}")

        results = []
        for method in methods:
            method_name = method.get('name')
            result = self.fuzz_method(bus, service, path, interface, method)
            if result:
                results.extend(result)

        return results

    def fuzz_all(self, targets: List[Dict], bus_type='session'):
        """Fuzz 所有目标"""
        print(f"\n[*] 开始 fuzz {len(targets)} 个目标")
        print(f"[*] Payload: 随机 GUID")

        try:
            if bus_type == 'system':
                bus = dbus.SystemBus()
            else:
                bus = dbus.SessionBus()
        except Exception as e:
            print(f"[!] 无法连接到总线: {e}")
            return []

        all_results = []

        for idx, target in enumerate(targets, 1):
            print(f"\n[{idx}/{len(targets)}]", end='')
            results = self.fuzz_target(bus, target)
            all_results.extend(results)

            # 显示进度
            print(f"    已调用: {self.total_calls}, 成功: {self.success_calls}, 错误: {self.error_calls}")

        return all_results


def main():
    parser = argparse.ArgumentParser(description='DBus 接口 Fuzz 工具 - 实时枚举模式')
    parser.add_argument('-o', '--output', default='dbus_fuzz_results.json',
                        help='输出结果文件路径')
    parser.add_argument('--bus', choices=['session', 'system'], default='system',
                        help='DBus 总线类型')
    parser.add_argument('--filter', dest='filter_name',
                        help='只测试包含指定字符串的服务')
    parser.add_argument('--no-check', action='store_true',
                        help='不检查命令执行结果')
    parser.add_argument('--delay', type=float, default=0.1,
                        help='每次调用后的延迟(秒)')

    args = parser.parse_args()

    print("="*60)
    print("DBus 接口 Fuzz 工具 - 实时枚举模式")
    print("="*60)
    print(f"[!] 警告: 仅用于授权的安全测试")
    print(f"[*] 使用随机 GUID 作为 payload")
    print(f"[*] 总线类型: {args.bus}")
    if args.filter_name:
        print(f"[*] 过滤器: {args.filter_name}")

    # 实时枚举接口
    targets = enumerate_dbus_interfaces(args.bus, args.filter_name)

    if not targets:
        print("[!] 没有找到可测试的目标")
        return

    # 开始 fuzz
    fuzzer = DBusFuzzer(check_result=not args.no_check, delay=args.delay)
    results = fuzzer.fuzz_all(targets, bus_type=args.bus)

    # 保存结果
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("\n" + "="*60)
    print("Fuzz 结果汇总:")
    print("="*60)
    print(f"  总尝试次数: {fuzzer.total_calls}")
    print(f"  成功调用: {fuzzer.success_calls}")
    print(f"  错误/跳过: {fuzzer.error_calls}")
    print(f"  结果已保存到: {args.output}")

    # 显示可能的成功调用
    potential_hits = [r for r in results if r.get('exec_detected')]
    if potential_hits:
        print("\n[!] 可能的成功调用:")
        for hit in potential_hits:
            print(f"  {hit['service']}::{hit['interface']}.{hit['method']}()")
            print(f"    Payload: {hit['payload']}")
    else:
        print("\n[*] 未检测到明显的命令执行")


if __name__ == '__main__':
    main()
