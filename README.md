# DbusFuzz
DBus 接口 Fuzz 工具
实时枚举 DBus 接口并测试命令注入漏洞
测试目标: 执行 dde-calendar 命令

!!! 警告: 此工具仅用于授权的安全测试 !!!

用法:
    python3 fuzz_dbus.py                    # 实时枚举并 fuzz 所有接口
    python3 fuzz_dbus.py --bus system       # 测试系统总线
    python3 fuzz_dbus.py --filter deepin    # 只测试包含 deepin 的服务
