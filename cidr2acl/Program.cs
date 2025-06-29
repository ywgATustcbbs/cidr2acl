using System;
using System.Collections.Generic;
using System.Net;

class CidrToAclConverter
{
    static void Main(string[] args)
    {
        // 输入CIDR列表（实际应用中可从文件读取）
        var cidrList = new List<string>
        {
            "1.0.1.0/24",
            "1.0.8.0/22",
            "1.15.0.0/16",
            "1.88.0.0/14",
            "223.202.248.0/22",
            "223.223.176.0/20"
        };

        int ruleNumber = 5; // 起始规则编号
        var aclCommands = new List<string>();

        foreach (var cidr in cidrList)
        {
            // 解析CIDR格式
            var parts = cidr.Split('/');
            if (parts.Length != 2) continue;

            var ipAddress = IPAddress.Parse(parts[0]);
            var prefixLength = int.Parse(parts[1]);

            // 计算反掩码(wildcard mask)
            var wildcardMask = CalculateWildcardMask(prefixLength);

            // 生成ACL命令
            aclCommands.Add($"rule {ruleNumber} permit ip destination {ipAddress} {wildcardMask}");
            ruleNumber += 5; // 规则号递增
        }

        // 输出结果
        Console.WriteLine("acl number 3100");
        foreach (var cmd in aclCommands)
        {
            Console.WriteLine($" {cmd}");
        }
        Console.WriteLine("quit");
    }

    static string CalculateWildcardMask(int prefixLength)
    {
        // 计算32位反掩码
        uint mask = 0xFFFFFFFF;
        mask <<= (32 - prefixLength);
        mask = ~mask;

        // 转换为IP格式
        byte[] bytes = BitConverter.GetBytes(mask);
        Array.Reverse(bytes); // 转换为大端序
        return new IPAddress(bytes).ToString();
    }
}