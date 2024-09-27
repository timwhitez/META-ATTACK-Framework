# META-ATT-CK-Framework
A knowledge base of actionable offensive security techniques based on ATT&amp;CK Framework

### 1. 准备阶段（Preparation）
攻击者在正式攻击前所做的所有准备工作。

  #### 1.1 目标选择（Target Selection）
    - 识别潜在目标
    - 评估目标价值
    - 确定攻击优先级
    
  #### 1.2 资源准备（Resource Preparation）
    - 工具和漏洞库准备
    - 攻击基础设施搭建（如C2服务器）
    - 掩饰手段准备（如VPN、代理）


### 2. 初始访问（Initial Access）
攻击者尝试获得对目标系统的初步访问权限。
  
  #### 2.1 社会工程（Social Engineering）
    - 网络钓鱼
    - 电话钓鱼
    - 假冒身份
  
  #### 2.2 技术攻击（Technical Exploitation）
    - 漏洞利用
    - 恶意软件植入
    - 网络服务攻击
  
  #### 2.3 合法途径（Legitimate Access）
    - 利用被盗的合法凭证
    - 第三方供应商漏洞


### 3. 建立立足点（Establish Foothold）
攻击者在目标系统中建立持久的访问权限。
  
  #### 3.1 后门植入（Backdoor Implantation）
    - 安装恶意软件
    - 创建隐藏账户
    - 修改系统配置
    
  #### 3.2 持久化机制（Persistence Mechanism）
    - 注册表修改
    - 启动项添加
    - 定时任务创建


### 4. 内部侦察（Internal Reconnaissance）
攻击者在目标网络内部收集信息，以便进一步行动。
  
  #### 4.1 网络扫描（Network Scanning）
    - 端口扫描
    - 服务识别
    - 内网拓扑图绘制
    
  #### 4.2 资产识别（Asset Identification）
    - 关键资产定位
    - 数据库和文件服务器识别
    - 安全设备识别
  
  #### 4.3 凭证收集（Credential Harvesting）
    - 密码抓取
    - 会话劫持
    - 凭证重放


### 5. 扩展访问（Lateral Movement）
攻击者尝试在目标网络中横向移动以获取更多权限。

  #### 5.1 凭证利用（Credential Utilization）
    - 使用收集到的凭证进行登录
    - 凭证重放攻击
    - 会话劫持
    
  #### 5.2 远程服务利用（Remote Service Exploitation）
    - RDP
    - SSH
    - SMB
  
  #### 5.3 网络横向移动（Lateral Movement Techniques）
    - 内网扫描
    - 共享文件利用
    - 管理工具利用


### 6. 权限提升（Privilege Escalation）
攻击者尝试提升其在目标系统中的权限。
  
  #### 6.1 本地提权（Local Privilege Escalation）
    - 漏洞利用
    - 密码破解
    - 提权工具

  #### 6.2 应用提权（Application Privilege Escalation）
    - 应用漏洞利用
    - 配置错误利用
    - 应用提权工具


### 7. 数据窃取与破坏（Data Exfiltration and Destruction）
攻击者尝试窃取或破坏目标系统中的数据。

  #### 7.1 数据收集（Data Collection）
    - 文件收集
    - 数据库导出
    - 敏感信息定位
    
  #### 7.2 数据传输（Data Exfiltration）
    - 网络传输
    - 外部存储设备
    - 隐蔽通道
  
  #### 7.3 数据隐藏（Data Hiding）
    - 数据加密
    - 隐写术
    - 文件伪装
    
  #### 7.4 数据破坏（Data Destruction）
    - 文件删除
    - 数据擦除
    - 数据篡改
    

### 8. 任务完成与撤离（Mission Completion and Evacuation）
攻击者完成任务后，尝试撤离并掩盖其踪迹。
  
  #### 8.1 任务完成（Mission Completion）
    - 目标信息获取
    - 目标系统控制
    - 目标资源利用
  
  #### 8.2 痕迹清理（Covering Tracks）
    - 日志清除
    - 痕迹擦除
    - 恶意软件删除
  
  #### 8.3 撤离（Evacuation）
    - 断开连接
    - 撤销基础设施
    - 恢复环境


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
