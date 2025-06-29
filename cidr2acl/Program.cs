using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

class CidrToAclConverter
{
    static void Main(string[] args)
    {
        string filePath = @"C:\Users\ustcy\Desktop\unicom-cidr.txt";
        
        // 检查文件是否存在
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"文件不存在: {filePath}");
            return;
        }

        var cidrList = new List<string>();
        
        // 从文件读取CIDR记录
        try
        {
            cidrList = new List<string>(File.ReadAllLines(filePath));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"读取文件时出错: {ex.Message}");
            return;
        }

        int ruleNumber = 5; // 起始规则编号
        var aclCommands = new List<string>();

        // 添加ACL头部
        aclCommands.Add("acl number 3100");

        foreach (var cidr in cidrList)
        {
            // 跳过空行
            if (string.IsNullOrWhiteSpace(cidr))
                continue;
                
            // 解析CIDR格式
            var parts = cidr.Split('/');
            if (parts.Length != 2) continue;

            try
            {
                var ipAddress = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);

                // 计算反掩码(wildcard mask)
                var wildcardMask = CalculateWildcardMask(prefixLength);

                // 生成ACL命令
                aclCommands.Add($"rule {ruleNumber} permit ip destination {ipAddress} {wildcardMask}");
                ruleNumber += 5; // 规则号递增
            }
            catch (Exception ex)
            {
                Console.WriteLine($"解析CIDR记录 '{cidr}' 时出错: {ex.Message}");
            }
        }

        // 添加ACL尾部
        aclCommands.Add("quit");

        // 生成输出文件路径（与输入文件相同目录）
        string outputDirectory = Path.GetDirectoryName(filePath);
        string outputPath = Path.Combine(outputDirectory, "acl.txt");

        // 写入文件
        try
        {
            File.WriteAllLines(outputPath, aclCommands);
            Console.WriteLine($"ACL命令已成功写入: {outputPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"写入文件时出错: {ex.Message}");
        }
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