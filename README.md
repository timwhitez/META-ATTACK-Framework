# META-ATT-CK-Framework
A knowledge base of actionable offensive security techniques based on ATT&CK Framework

### 1. 准备阶段（Preparation）
攻击者在正式攻击前所做的所有准备工作。
[Reconnaissance (TA0043)]

#### 1.1 目标选择（Target Selection）
- 识别潜在目标 [Gather Victim Identity Information (T1589)]
- 评估目标价值 [Gather Victim Org Information (T1591)]
- 确定攻击优先级

#### 1.2 资源准备（Resource Preparation）
- 工具和漏洞库准备 [Develop Capabilities (T1587)]
- 攻击基础设施搭建（如C2服务器）[Acquire Infrastructure (T1583)]
- 掩饰手段准备（如VPN、代理）[Proxy (T1090)]

#### 1.3 情报收集（Intelligence Gathering）
- 开源情报收集 [Search Open Websites/Domains (T1593)]
- 社交媒体情报收集 [Search Social Media (T1593.001)]
- 技术情报收集 [Search Victim-Owned Websites (T1594)]

### 2. 初始访问（Initial Access）
攻击者尝试获得对目标系统的初步访问权限。
[Initial Access (TA0001)]

#### 2.1 社会工程（Social Engineering）
- 网络钓鱼 [Phishing (T1566)]
- 电话钓鱼 [Phishing: Spearphishing via Service (T1566.003)]
- 假冒身份 [Impersonation (T1534)]

#### 2.2 技术攻击（Technical Exploitation）
- 漏洞利用 [Exploit Public-Facing Application (T1190)]
- 恶意软件植入 [Malware (T1587.001)]
- 网络服务攻击 [External Remote Services (T1133)]

#### 2.3 合法途径（Legitimate Access）
- 利用被盗的合法凭证 [Valid Accounts (T1078)]
- 第三方供应商漏洞 [Supply Chain Compromise (T1195)]

#### 2.4 硬件攻击（Hardware-based Attacks）
- USB投放 [Replication Through Removable Media (T1091)]
- 恶意硬件植入 [Hardware Additions (T1200)]

### 3. 建立立足点（Establish Foothold）
攻击者在目标系统中建立持久的访问权限。
[Persistence (TA0003)]

#### 3.1 后门植入（Backdoor Implantation）
- 安装恶意软件 [Implant Internal Image (T1525)]
- 创建隐藏账户 [Create Account (T1136)]
- 修改系统配置 [Modify System Image (T1601)]

#### 3.2 持久化机制（Persistence Mechanism）
- 注册表修改 [Registry Run Keys / Startup Folder (T1547.001)]
- 启动项添加 [Boot or Logon Autostart Execution (T1547)]
- 定时任务创建 [Scheduled Task/Job (T1053)]

#### 3.3 权限维持（Privilege Maintenance）
- 凭证窃取 [OS Credential Dumping (T1003)]
- 访问令牌操作 [Access Token Manipulation (T1134)]

### 4. 内部侦察（Internal Reconnaissance）
攻击者在目标网络内部收集信息，以便进一步行动。
[Discovery (TA0007)]

#### 4.1 网络扫描（Network Scanning）
- 端口扫描 [Network Service Scanning (T1046)]
- 服务识别 [System Service Discovery (T1007)]
- 内网拓扑图绘制 [Network Sniffing (T1040)]

#### 4.2 资产识别（Asset Identification）
- 关键资产定位 [System Network Configuration Discovery (T1016)]
- 数据库和文件服务器识别 [File and Directory Discovery (T1083)]
- 安全设备识别 [Security Software Discovery (T1518.001)]

#### 4.3 凭证收集（Credential Harvesting）
- 密码抓取 [Credentials from Password Stores (T1555)]
- 会话劫持 [Steal or Forge Kerberos Tickets (T1558)]
- 凭证重放 [Pass the Hash (T1550.002)]

#### 4.4 用户和权限枚举（User and Permission Enumeration）
- 用户账户发现 [Account Discovery (T1087)]
- 权限组枚举 [Permission Groups Discovery (T1069)]

### 5. 扩展访问（Lateral Movement）
攻击者尝试在目标网络中横向移动以获取更多权限。
[Lateral Movement (TA0008)]

#### 5.1 凭证利用（Credential Utilization）
- 使用收集到的凭证进行登录 [Use Alternate Authentication Material (T1550)]
- 凭证重放攻击 [Pass the Ticket (T1550.003)]
- 会话劫持 [Exploitation of Remote Services (T1210)]

#### 5.2 远程服务利用（Remote Service Exploitation）
- RDP [Remote Services: Remote Desktop Protocol (T1021.001)]
- SSH [Remote Services: SSH (T1021.004)]
- SMB [Remote Services: SMB/Windows Admin Shares (T1021.002)]

#### 5.3 网络横向移动（Lateral Movement Techniques）
- 内网扫描 [Network Service Scanning (T1046)]
- 共享文件利用 [Taint Shared Content (T1080)]
- 管理工具利用 [Remote Services: Distributed Component Object Model (T1021.003)]

#### 5.4 内部代理（Internal Proxy）
- 端口转发 [Protocol Tunneling (T1572)]
- SOCKS代理 [Proxy: Multi-hop Proxy (T1090.003)]

### 6. 权限提升（Privilege Escalation）
攻击者尝试提升其在目标系统中的权限。
[Privilege Escalation (TA0004)]

#### 6.1 本地提权（Local Privilege Escalation）
- 漏洞利用 [Exploitation for Privilege Escalation (T1068)]
- 密码破解 [Brute Force (T1110)]
- 提权工具 [Process Injection (T1055)]

#### 6.2 应用提权（Application Privilege Escalation）
- 应用漏洞利用 [Exploitation for Privilege Escalation (T1068)]
- 配置错误利用 [Abuse Elevation Control Mechanism (T1548)]
- 应用提权工具 [Elevated Execution with Prompt (T1548.004)]

#### 6.3 操作系统内核提权（OS Kernel Privilege Escalation）
- 内核漏洞利用 [Exploitation for Privilege Escalation (T1068)]
- 驱动程序操作 [Boot or Logon Autostart Execution: Kernel Modules and Extensions (T1547.006)]

### 7. 数据窃取与破坏（Data Exfiltration and Destruction）
攻击者尝试窃取或破坏目标系统中的数据。
[Exfiltration (TA0010), Impact (TA0040)]

#### 7.1 数据收集（Data Collection）
- 文件收集 [Automated Collection (T1119)]
- 数据库导出 [Data from Local System (T1005)]
- 敏感信息定位 [Data Staged (T1074)]

#### 7.2 数据传输（Data Exfiltration）
- 网络传输 [Exfiltration Over C2 Channel (T1041)]
- 外部存储设备 [Exfiltration Over Physical Medium (T1052)]
- 隐蔽通道 [Data Encoding (T1132)]

#### 7.3 数据隐藏（Data Hiding）
- 数据加密 [Obfuscated Files or Information (T1027)]
- 隐写术 [Steganography (T1027.003)]
- 文件伪装 [Masquerading (T1036)]

#### 7.4 数据破坏（Data Destruction）
- 文件删除 [File Deletion (T1070.004)]
- 数据擦除 [Data Destruction (T1485)]
- 数据篡改 [Data Manipulation (T1565)]

#### 7.5 勒索攻击（Ransomware）
- 数据加密 [Data Encrypted for Impact (T1486)]
- 勒索消息投放 [Data Encrypted for Impact (T1486)]

### 8. 任务完成与撤离（Mission Completion and Evacuation）
攻击者完成任务后，尝试撤离并掩盖其踪迹。
[Impact (TA0040), Defense Evasion (TA0005)]

#### 8.1 任务完成（Mission Completion）
- 目标信息获取 [Data from Local System (T1005)]
- 目标系统控制 [Remote Access Software (T1219)]
- 目标资源利用 [Resource Hijacking (T1496)]

#### 8.2 痕迹清理（Covering Tracks）
- 日志清除 [Indicator Removal on Host (T1070)]
- 痕迹擦除 [Clear Windows Event Logs (T1070.001)]
- 恶意软件删除 [File Deletion (T1070.004)]

#### 8.3 撤离（Evacuation）
- 断开连接 [Network Denial of Service (T1498)]
- 撤销基础设施 [Resource Hijacking (T1496)]
- 恢复环境 [Restore from Backup (T1059)]

#### 8.4 后门维护（Backdoor Maintenance）
- 隐蔽通道维护 [Non-Standard Port (T1571)]
- 定期连接测试 [Automated Exfiltration (T1020)]

### 9. 评估与学习（Assessment and Learning）
攻击者对整个攻击过程进行评估和总结，以改进未来的攻击。

#### 9.1 成果评估（Result Assessment）
- 目标达成情况评估
- 成功与失败分析

#### 9.2 技术改进（Technical Improvement）
- 工具和技术更新
- 新的攻击策略开发

#### 9.3 经验总结（Experience Summary）
- 攻击日志记录
- 经验教训总结

#### 9.4 威胁情报分析（Threat Intelligence Analysis）
- 防御措施评估
- 新兴威胁研究
  
