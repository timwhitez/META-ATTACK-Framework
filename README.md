# META-ATT&CK-Framework
A comprehensive matrix base of actionable offensive security techniques based on ATT&CK Framework

基于 ATT&CK 框架的可操作攻击性安全技术的综合矩阵

![](./meta-attack-matrix.svg)

![](./meta-attack-matrix_en.svg)

## 1. Strategic Planning | 战略规划 [Reconnaissance (TA0043), Resource Development (TA0042)]

This phase involves pre-attack preparation work, including target selection, resource preparation, and intelligence gathering. | 此阶段涉及攻击前的准备工作，包括目标选择、资源准备和情报收集。

### 1.1 Target Selection | 目标选择 
- Identification of high-value targets | 高价值目标识别 [Gather Victim Identity Information (T1589)]
- Geopolitical considerations | 地缘政治考量 [Gather Victim Org Information (T1591)]
- Economic benefit assessment | 经济利益评估 [Gather Victim Org Information (T1591)]

### 1.2 Attack Resource Preparation | 攻击资源准备
- Customized malware development | 定制化恶意软件开发 [Develop Capabilities (T1587)]
- Zero-day vulnerability acquisition and stockpiling | 零日漏洞获取和储备 [Exploit Public-Facing Application (T1190)]
- Multi-layer proxy infrastructure setup | 多层代理基础设施搭建 [Acquire Infrastructure (T1583)]

### 1.3 Intelligence Gathering | 情报收集
- Deep open-source intelligence (OSINT) collection | 深度开源情报（OSINT）收集 [Search Open Websites/Domains (T1593)]
- Supply chain analysis | 供应链分析 [Gather Victim Org Information (T1591)]
- Social engineering information collection | 社交工程信息收集 [Phishing for Information (T1598)]

## 2. Initial Access | 初始访问 [Initial Access (TA0001)]

This phase involves methods used by attackers to first enter the target network. | 此阶段涉及攻击者首次进入目标网络的方法。

### 2.1 Social Engineering Attacks | 社会工程攻击
- Targeted spear-phishing | 定向鱼叉式网络钓鱼 [Phishing: Spearphishing Attachment (T1566.001)]
- Watering hole attacks | 水坑攻击 [Drive-by Compromise (T1189)]
- Impersonation of trusted entities | 假冒可信实体 [Impersonation (T1534)]

### 2.2 Technical Vulnerability Exploitation | 技术漏洞利用
- Zero-day vulnerability exploitation | 零日漏洞利用 [Exploit Public-Facing Application (T1190)]
- Known vulnerability exploitation (e.g., Log4j, ProxyLogon) | 已知漏洞利用（如Log4j、ProxyLogon）[Exploit Public-Facing Application (T1190)]
- Misconfiguration exploitation | 配置错误利用 [Exploit Public-Facing Application (T1190)]

### 2.3 Supply Chain Attacks | 供应链攻击
- Software update channel hijacking | 软件更新渠道劫持 [Supply Chain Compromise (T1195)]
- Third-party service provider infiltration | 第三方服务提供商渗透 [Trusted Relationship (T1199)]
- Open-source component pollution | 开源组件污染 [Supply Chain Compromise (T1195)]

## 3. Foothold Establishment | 立足点建立 [Persistence (TA0003), Defense Evasion (TA0005)]

This phase involves methods used by attackers to establish long-term access to the target system. | 此阶段涉及攻击者在目标系统中建立长期访问的方法。

### 3.1 Persistence Mechanisms | 持久化机制
- Boot or login autostart execution | 引导或登录自启动执行 [Boot or Logon Autostart Execution (T1547)]
- Create or modify system processes | 创建或修改系统进程 [Create or Modify System Process (T1543)]
- Registry hijacking | 注册表劫持 [Hijack Execution Flow (T1574)]

### 3.2 Backdoor Implantation | 后门植入
- Firmware-level backdoors | 固件级后门 [BIOS/UEFI Firmware Modifications (T1542.001)]
- Memory-resident malicious code | 内存驻留恶意代码 [Reflective Code Loading (T1620)]
- Signed software hijacking | 签名软件劫持 [Hijack Execution Flow (T1574)]

### 3.3 Defense Evasion | 防御规避
- Anti-VM and sandbox techniques | 反虚拟机和沙箱技术 [Virtualization/Sandbox Evasion (T1497)]
- Obfuscation and encryption | 混淆和加密 [Obfuscated Files or Information (T1027)]
- Signature forgery | 签名伪造 [Subvert Trust Controls (T1553)]

## 4. Privilege Escalation | 权限提升 [Privilege Escalation (TA0004)]

This phase involves methods used by attackers to gain higher-level system privileges. | 此阶段涉及攻击者获取更高级别系统权限的方法。

### 4.1 Local Privilege Escalation | 本地权限提升
- Kernel vulnerability exploitation | 内核漏洞利用 [Exploitation for Privilege Escalation (T1068)]
- DLL hijacking | DLL劫持 [Hijack Execution Flow: DLL Search Order Hijacking (T1574.001)]
- Scheduled task abuse | 计划任务滥用 [Scheduled Task/Job (T1053)]

### 4.2 Domain Privilege Escalation | 域权限提升
- Kerberoasting | Kerberoasting [Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)]
- DCSync attacks | DCSync攻击 [OS Credential Dumping: DCSync (T1003.006)]
- Domain trust relationship exploitation | 域信任关系利用 [Domain Trust Discovery (T1482)]

### 4.3 Cloud Environment Privilege Escalation | 云环境权限提升
- Role impersonation | 角色假冒 [Valid Accounts (T1078)]
- Misconfiguration exploitation | 配置错误利用 [Unsecured Credentials: Cloud Instance Metadata API (T1552.005)]
- Managed identity abuse | 托管身份滥用 [Use of Application Access Token (T1550.001)]

## 5. Internal Reconnaissance | 内部侦察 [Discovery (TA0007)]

This phase involves methods used by attackers to gather information within the target network. | 此阶段涉及攻击者在目标网络内部收集信息的方法。

### 5.1 Network Discovery | 网络发现
- Passive network mapping | 被动网络映射 [Network Sniffing (T1040)]
- Active Directory enumeration | 活动目录枚举 [Domain Trust Discovery (T1482)]
- Service discovery | 服务发现 [System Service Discovery (T1007)]

### 5.2 Asset Identification | 资产识别
- Critical data storage location identification | 关键数据存储位置识别 [Data from Information Repositories (T1213)]
- Business-critical system localization | 业务关键系统定位 [System Location Discovery (T1614)]
- High-value target identification | 高价值目标识别 [System Network Configuration Discovery (T1016)]

### 5.3 Vulnerability Scanning | 漏洞扫描
- Internal system vulnerability scanning | 内部系统漏洞扫描 [Network Service Scanning (T1046)]
- Misconfiguration identification | 错误配置识别 [Network Service Scanning (T1046)]
- Unpatched system discovery | 未打补丁系统发现 [Network Service Scanning (T1046)]

## 6. Lateral Movement | 横向移动 [Lateral Movement (TA0008)]

This phase involves methods used by attackers to expand their control within the target network. | 此阶段涉及攻击者在目标网络内部扩展控制范围的方法。

### 6.1 Credential Exploitation | 凭证利用
- Pass the hash | 传递哈希 [Use Alternate Authentication Material: Pass the Hash (T1550.002)]
- Golden ticket and silver ticket attacks | 黄金票据和白银票据攻击 [Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001)]
- Credential injection | 凭证注入 [Account Manipulation: SSH Authorized Keys (T1098.004)]

### 6.2 Remote Service Exploitation | 远程服务利用
- Exploitation of undocumented remote procedure calls | 利用未记录的远程调用过程 [Exploitation of Remote Services (T1210)]
- Exploitation of trusted management protocols (e.g., WMI, PowerShell Remoting) | 利用可信管理协议（如WMI、PowerShell Remoting）[Remote Services (T1021)]
- RDP hijacking | RDP劫持 [Remote Services: Remote Desktop Protocol (T1021.001)]

### 6.3 Internal Network Manipulation | 内部网络操纵
- VLAN hopping | VLAN跳跃 [Exploitation of Remote Services (T1210)]
- Internal routing manipulation | 内部路由操纵 [Network Boundary Bridging (T1599)]
- ARP spoofing | ARP欺骗 [Network Sniffing (T1040)]

## 7. Data Acquisition and Exfiltration | 数据获取与渗出 [Collection (TA0009), Exfiltration (TA0010)]

This phase involves methods used by attackers to collect and transmit target data. | 此阶段涉及攻击者收集和传输目标数据的方法。

### 7.1 Data Discovery and Collection | 数据发现与收集
- Automated sensitive data identification | 自动化敏感数据识别 [Automated Collection (T1119)]
- Database content extraction | 数据库内容提取 [Data from Information Repositories (T1213)]
- File system scanning | 文件系统扫描 [File and Directory Discovery (T1083)]

### 7.2 Data Classification and Prioritization | 数据分类与优先级排序
- Keyword-based data classification | 基于关键字的数据分类 [Automated Collection (T1119)]
- Data sensitivity assessment | 数据敏感度评估 [Data Staged (T1074)]
- Data value analysis | 数据价值分析 [Data from Information Repositories (T1213)]

### 7.3 Covert Data Exfiltration | 隐蔽数据渗出
- DNS tunneling | DNS隧道 [Exfiltration Over Alternative Protocol: Exfiltration Over DNS (T1048.001)]
- Encrypted channel data transmission | 加密通道数据传输 [Encrypted Channel: Asymmetric Cryptography (T1573.002)]
- Steganography | 隐写术 [Steganography (T1027.003)]

## 8. Impact and Destruction | 影响与破坏 [Impact (TA0040)]

This phase involves methods used by attackers to cause damage or impact to the target system. | 此阶段涉及攻击者对目标系统造成破坏或影响的方法。

### 8.1 Data Manipulation | 数据操纵
- Targeted data tampering | 定向数据篡改 [Data Manipulation: Stored Data Manipulation (T1565.001)]
- Database pollution | 数据库污染 [Data Manipulation: Stored Data Manipulation (T1565.001)]
- Configuration file modification | 配置文件修改 [Data Manipulation: Stored Data Manipulation (T1565.001)]

### 8.2 System Destruction | 系统破坏
- Selective data erasure | 选择性数据擦除 [Data Destruction (T1485)]
- Critical system file deletion | 系统关键文件删除 [Data Destruction (T1485)]
- Boot record overwriting | 引导记录覆盖 [Data Destruction (T1485)]

### 8.3 Ransomware Attacks | 勒索攻击
- Data encryption | 数据加密 [Data Encrypted for Impact (T1486)]
- Ransom message delivery | 勒索消息投放 [Data Encrypted for Impact (T1486)]
- Payment system establishment | 支付系统建立 [Data Encrypted for Impact (T1486)]

## 9. Long-term Persistence | 长期驻留 [Persistence (TA0003), Command and Control (TA0011)]

This phase involves methods used by attackers to maintain long-term access and control. | 此阶段涉及攻击者维持长期访问和控制的方法。

### 9.1 Covert Communication Channels | 隐蔽通信通道
- Custom C2 protocols | 自定义C2协议 [Application Layer Protocol: Web Protocols (T1071.001)]
- Domain fronting | 域前置 [Domain Fronting (T1090.004)]
- Social media C2 | 社交媒体C2 [Application Layer Protocol: Web Protocols (T1071.001)]

### 9.2 Self-Update Mechanisms | 自我更新机制
- Modular malware architecture | 模块化恶意软件架构 [Software Packing (T1027.002)]
- Dynamic code injection | 动态代码注入 [Process Injection (T1055)]
- Remote configuration updates | 远程配置更新 [Ingress Tool Transfer (T1105)]

### 9.3 Alternate Access Points | 备用接入点
- Multiple backdoor deployment | 多重后门部署 [Create or Modify System Process (T1543)]
- Dormant agents | 休眠代理 [Scheduled Task/Job (T1053)]
- Hardware implants | 硬件植入 [Hardware Additions (T1200)]

## 10. Mission Completion | 行动完成 [Exfiltration (TA0010), Impact (TA0040)]

This phase involves methods used by attackers to complete their objectives and clean up their traces. | 此阶段涉及攻击者完成目标并清理痕迹的方法。

### 10.1 Objective Confirmation | 目标确认
- Data integrity verification | 数据完整性验证 [Data Staged (T1074)]
- Persistent access confirmation | 持久访问确认 [Automated Exfiltration (T1020)]
- Impact assessment | 影响评估 [Data Destruction (T1485)]

### 10.2 Trace Cleanup | 痕迹清理
- Log clearing and forging | 日志清除和伪造 [Indicator Removal: Clear Windows Event Logs (T1070.001)]
- Timestamp tampering | 时间戳篡改 [Timestomp (T1070.006)]
- Memory trace cleanup | 内存痕迹清理 [Indicator Removal on Host (T1070)]

### 10.3 Evacuation Strategy | 撤离策略
- Phased evacuation | 分阶段撤离 [Data Staged (T1074)]
- False evacuation decoys | 假撤离诱饵 [Exfiltration Over C2 Channel (T1041)]
- Automation of backdoor maintenance | 后门维护的自动化 [Automated Exfiltration (T1020)]

## 11. Post-Action Evaluation | 后行动评估 [No direct ATT&CK tactic correspondence | 无直接对应ATT&CK战术]

This phase involves methods used by attackers to evaluate the effectiveness of their actions and improve their capabilities. | 此阶段涉及攻击者评估行动效果并进行能力提升的方法。

### 11.1 Action Effectiveness Analysis | 行动效果分析
- Objective achievement assessment | 目标达成度评估
- Technical effectiveness analysis | 技术有效性分析
- Defense bypass success rate statistics | 防御绕过成功率统计

### 11.2 Intelligence Feedback | 情报反馈
- Target defense capability assessment | 目标防御能力评估
- New defense technology identification | 新防御技术识别
- Tactical adjustment recommendations | 战术调整建议

### 11.3 Capability Enhancement | 能力提升
- Tool and malware improvement | 工具和恶意软件改进
- New attack vector research | 新攻击向量研究
- Team skill training and improvement | 团队技能培训和提升
