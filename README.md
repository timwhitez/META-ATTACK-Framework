# META-ATT-CK-Framework
A comprehensive knowledge base of actionable offensive security techniques based on ATT&CK Framework and recent APT events

### 1. 准备阶段（Preparation）
[Reconnaissance (TA0043)]

#### 1.1 目标选择（Target Selection）
- 识别高价值目标 [Gather Victim Identity Information (T1589)]
- 评估目标安全态势 [Gather Victim Network Information (T1590)]
- 确定攻击优先级和时间线

#### 1.2 资源准备（Resource Preparation）
- 定制化恶意软件开发 [Develop Capabilities (T1587)]
- 多层代理基础设施搭建 [Acquire Infrastructure (T1583)]
- 零日漏洞获取和储备 [Exploit Public-Facing Application (T1190)]

#### 1.3 高级情报收集（Advanced Intelligence Gathering）
- 深度开源情报（OSINT）收集 [Search Open Websites/Domains (T1593)]
- 社交工程预备 [Phishing for Information (T1598)]
- 供应链情报收集 [Gather Victim Org Information (T1591)]

### 2. 初始访问（Initial Access）
[Initial Access (TA0001)]

#### 2.1 高级社会工程（Advanced Social Engineering）
- 定向鱼叉式网络钓鱼 [Phishing: Spearphishing Attachment (T1566.001)]
- 水坑攻击 [Drive-by Compromise (T1189)]
- 假冒可信实体 [Impersonation (T1534)]

#### 2.2 供应链攻击（Supply Chain Attack）
- 软件更新渠道劫持 [Supply Chain Compromise (T1195)]
- 第三方服务提供商渗透 [Trusted Relationship (T1199)]

#### 2.3 高级技术攻击（Advanced Technical Exploitation）
- 零日漏洞利用 [Exploit Public-Facing Application (T1190)]
- 自定义恶意固件 [Firmware Corruption (T1495)]
- 针对性网络钓鱼附件 [Phishing: Spearphishing Attachment (T1566.001)]

### 3. 建立立足点（Establish Foothold）
[Persistence (TA0003)]

#### 3.1 高级后门植入（Advanced Backdoor Implantation）
- 固件级后门 [BIOS/UEFI Firmware Modifications (T1542.001)]
- 内存驻留恶意代码 [Reflective Code Loading (T1620)]
- 签名软件劫持 [Hijack Execution Flow (T1574)]

#### 3.2 持久化机制（Advanced Persistence Mechanism）
- 引导或登录自启动执行 [Boot or Logon Autostart Execution (T1547)]
- 账户操作 [Account Manipulation (T1098)]
- 创建或修改系统进程 [Create or Modify System Process (T1543)]

#### 3.3 高级权限维持（Advanced Privilege Maintenance）
- 凭证盗取和伪造 [Forge Web Credentials (T1606)]
- 黄金票据攻击 [Steal or Forge Kerberos Tickets (T1558)]
- 影子凭证技术 [Modify Authentication Process (T1556)]

### 4. 内部侦察（Internal Reconnaissance）
[Discovery (TA0007)]

#### 4.1 高级网络扫描（Advanced Network Scanning）
- 被动网络映射 [Network Sniffing (T1040)]
- 协议分析 [Network Service Scanning (T1046)]
- 高级端口扫描技术（如SYN扫描、ACK扫描）

#### 4.2 高价值资产识别（High-Value Asset Identification）
- 活动目录枚举 [Domain Trust Discovery (T1482)]
- 关键数据存储位置识别 [Data from Information Repositories (T1213)]
- 业务关键系统定位 [System Location Discovery (T1614)]

#### 4.3 高级凭证收集（Advanced Credential Harvesting）
- 内存中的凭证提取 [OS Credential Dumping: LSASS Memory (T1003.001)]
- 凭证保险箱攻击 [Credentials from Password Stores (T1555)]
- 跨进程凭证窃取 [Credentials from Web Browsers (T1555.003)]

### 5. 横向移动（Lateral Movement）
[Lateral Movement (TA0008)]

#### 5.1 高级凭证利用（Advanced Credential Utilization）
- 传递哈希 [Use Alternate Authentication Material: Pass the Hash (T1550.002)]
- 黄金票据和白银票据攻击 [Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001)]
- 凭证注入 [Account Manipulation: SSH Authorized Keys (T1098.004)]

#### 5.2 高级远程服务利用（Advanced Remote Service Exploitation）
- 利用未记录的远程调用过程 [Exploitation of Remote Services (T1210)]
- 自定义C2协议 [Application Layer Protocol: Web Protocols (T1071.001)]
- 利用可信管理协议（如WMI、PowerShell Remoting）[Remote Services (T1021)]

#### 5.3 高级横向移动技术（Advanced Lateral Movement Techniques）
- 利用可信域关系 [Exploit Trust Relationships (T1563)]
- 内部网络跳板 [Internal Proxy (T1090)]
- 软件部署工具滥用 [Remote Services: Distributed Component Object Model (T1021.003)]

### 6. 权限提升（Privilege Escalation）
[Privilege Escalation (TA0004)]

#### 6.1 高级本地提权（Advanced Local Privilege Escalation）
- 内核漏洞利用 [Exploitation for Privilege Escalation (T1068)]
- DLL劫持 [Hijack Execution Flow: DLL Search Order Hijacking (T1574.001)]
- 计划任务滥用 [Scheduled Task/Job (T1053)]

#### 6.2 高级应用提权（Advanced Application Privilege Escalation）
- 应用程序逻辑缺陷利用
- 配置错误利用 [Abuse Elevation Control Mechanism (T1548)]
- 第三方插件漏洞利用

#### 6.3 域权限提升（Domain Privilege Escalation）
- Kerberoasting [Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)]
- DCSync攻击 [OS Credential Dumping: DCSync (T1003.006)]
- 域信任关系利用 [Domain Trust Discovery (T1482)]

### 7. 数据窃取与破坏（Data Exfiltration and Destruction）
[Exfiltration (TA0010), Impact (TA0040)]

#### 7.1 高级数据收集（Advanced Data Collection）
- 自动化敏感数据识别 [Automated Collection (T1119)]
- 分布式数据收集 [Data from Information Repositories (T1213)]
- 数据分类和优先级排序

#### 7.2 隐蔽数据传输（Covert Data Exfiltration）
- DNS隧道 [Exfiltration Over Alternative Protocol: Exfiltration Over DNS (T1048.001)]
- 加密通道数据传输 [Encrypted Channel: Asymmetric Cryptography (T1573.002)]
- 隐写术 [Steganography (T1027.003)]

#### 7.3 高级数据隐藏（Advanced Data Hiding）
- 多层加密 [Obfuscated Files or Information: Software Packing (T1027.002)]
- 内存中的数据处理 [Reflective Code Loading (T1620)]
- 分布式存储 [Data Staging (T1074)]

#### 7.4 精准数据破坏（Precision Data Destruction）
- 定向数据篡改 [Data Manipulation: Stored Data Manipulation (T1565.001)]
- 选择性数据擦除 [Data Destruction (T1485)]
- 勒索软件部署 [Data Encrypted for Impact (T1486)]

### 8. 任务完成与撤离（Mission Completion and Evacuation）
[Impact (TA0040), Defense Evasion (TA0005)]

#### 8.1 目标达成确认（Objective Achievement Confirmation）
- 数据完整性验证
- 持久访问确认
- 影响评估

#### 8.2 高级痕迹清理（Advanced Covering Tracks）
- 日志伪造和删除 [Indicator Removal: Clear Windows Event Logs (T1070.001)]
- 时间戳篡改 [Timestomp (T1070.006)]
- 内存痕迹清理 [Indicator Removal on Host (T1070)]

#### 8.3 隐蔽撤离（Covert Evacuation）
- 分阶段撤离
- 假撤离诱饵
- 后门维护的自动化 [Automated Exfiltration (T1020)]

#### 8.4 长期访问准备（Preparation for Long-Term Access）
- 隐蔽通道维护 [Protocol Tunneling (T1572)]
- 备用接入点部署
- 自我更新机制实现

### 9. 评估与学习（Assessment and Learning）
[未在ATT&CK框架中直接对应]

#### 9.1 行动后评估（Post-Action Evaluation）
- 目标达成度分析
- 技术有效性评估
- 防御绕过成功率分析

#### 9.2 战术技术优化（Tactical and Technical Optimization）
- 工具和恶意软件改进
- 新攻击向量研究
- 对抗性仿真优化

#### 9.3 情报反馈（Intelligence Feedback）
- 目标防御能力评估
- 新防御技术识别
- 战术调整建议

#### 9.4 能力提升（Capability Enhancement）
- 新兴技术学习（如AI辅助攻击）
- 跨领域知识整合（如硬件安全、云安全）
- 团队技能培训和提升
