



## What is Security Auditing?

Security auditing is a structured process that evaluates and verifies an organization's security measures to ensure their effectiveness and compliance with relevant standards, policies, and regulations. It involves reviewing information systems, networks, and procedures to identify vulnerabilities and areas for improvement. Security audits often lead to penetration testing and help ensure adherence to compliance requirements or regulations.

### Importance of Security Auditing

1. **Identifying Vulnerabilities and Weaknesses**: Audits reveal vulnerabilities in systems and infrastructure that could be exploited by attackers, ensuring security controls are updated and effective to prevent breaches.
2. **Ensuring Compliance**: Organizations must comply with various regulatory frameworks like GDPR, HIPAA, PCI DSS, or ISO 27001. Security audits verify compliance, avoiding legal or financial penalties.
3. **Enhancing Risk Management**: Audits assess the overall security posture, prioritizing risks based on potential impact. Findings guide risk mitigation strategies to strengthen security.
4. **Improving Security Policies & Procedures**: Audits review and improve the effectiveness of security policies, fostering a stronger security culture within the organization.
5. **Supporting Business Objectives**: A secure environment ensures critical business operations are protected from disruption, fostering customer trust and confidence by handling data securely.
6. **Continuous Improvement**: Security auditing is ongoing, ensuring that security measures adapt to emerging threats and maintain a proactive security posture.

### Essential Terminology

- **Security Policies** - Security policies are formal documents outlining an organization's security goals, guidelines, and procedures. They provide the framework for enforcing security controls.
- **Compliance** - Compliance ensures adherence to regulatory requirements, industry standards, and internal policies, helping organizations meet legal obligations and follow best security practices.
- **Vulnerability** - A vulnerability is a weakness in a system or process that can be exploited. Identifying them is crucial for strengthening security defenses.
- **Control** - A control is a safeguard to mitigate risks and protect information. It helps prevent, detect, or respond to security threats and vulnerabilities.
- **Risk Assessment** - Risk assessment identifies, analyzes, and evaluates risks to information assets. It helps prioritize security measures based on risk impact and likelihood.
- **Audit Trail** - An audit trail is a chronological record of system activities, providing evidence of actions for accountability and traceability in audits and investigations.
- **Compliance Audit** - A compliance audit examines if an organization adheres to regulatory and industry standards, ensuring legal conformity and identifying areas for improvement.
- **Access Control** - Access control regulates who can access systems or data and what actions they can take. It prevents unauthorized access and misuse of sensitive information.
- **Audit Report** - An audit report documents audit findings, conclusions, and recommendations, offering guidance to improve security practices.

### Security Auditing Process

1. **Planning and Preparation** : Define the audit's objectives and scope, including the systems and controls to be evaluated. Gather relevant documentation like policies and network diagrams, establish the audit team, and set a schedule.
    
2. **Information Gathering**: Review security policies and procedures, interview key personnel to identify gaps, and collect technical data on system configurations, network architecture, and controls.
    
3. **Risk Assessment**: Identify critical assets and potential threats, evaluate vulnerabilities in systems, and assign risk levels based on the likelihood and impact of these threats.
    
4. **Audit Execution**: Conduct technical assessments like vulnerability scans and penetration tests. Verify compliance with regulations and evaluate the effectiveness of security controls.
    
5. **Analysis and Evaluation**: Analyze audit findings to identify weaknesses, compare results against industry standards, and prioritize issues based on their severity and impact.
    
6. **Reporting**: Create a detailed report of the findings, including vulnerabilities and non-compliance issues, and provide actionable recommendations. Present the report to stakeholders for discussion.
    
7. **Remediation**: Develop and implement remediation plans to address findings. Follow up with audits to ensure changes are effective, and monitor security posture for continuous improvement.


**Types of Security Audits**

Security audits are categorized based on their scope, methodology, and organizational focus. They are essential for evaluating the effectiveness of security measures, compliance, and internal controls, helping penetration testers guide their testing.
- **Internal Audits** are conducted by an organization’s internal team to assess the effectiveness of internal controls and compliance with policies. These audits offer insight into the company’s security posture and help identify areas needing further testing. An example is reviewing user access controls.
- **External Audits** are performed by independent third-party auditors to provide an objective evaluation of security measures and external compliance standards. These audits, such as PCI DSS audits, serve as benchmarks for organizational security.
- **Compliance Audits** focus on ensuring that the organization meets specific regulatory and industry standards like GDPR, HIPAA, or PCI DSS. They help identify regulatory gaps that penetration testers can address. An example is a HIPAA audit for protecting patient data.
- **Technical Audits** focus on evaluating the technical components of an organization’s IT infrastructure, including hardware, software, and network configurations. They provide detailed insights into the technical controls and help identify vulnerabilities that penetration testers can target. An example might involve reviewing firewall configurations to ensure they secure the network perimeter effectively.
- **Network Audits** specifically assess the security of the organization’s network infrastructure, including routers, switches, and firewalls. These audits help uncover weaknesses in network design and configurations, which penetration testers can exploit. For example, insecure protocols in data transmission might be identified during a network audit.
- **Application Audits** examine the security of software applications, focusing on areas like code quality, authentication, input validation, and data handling. These audits reveal vulnerabilities that penetration testers can exploit to simulate real-world attack scenarios. For instance, an application audit could expose security flaws like SQL injection or cross-site scripting (XSS).

## Auditing-and-Pentesting


Security audits and penetration tests are distinct but complementary assessments, each with different goals, scope, and outcomes. Understanding these differences is essential for effective penetration testing and how these assessments relate to one another.

- **Security Audits** evaluate an organization’s overall security posture by assessing its compliance with policies, standards, and regulations. These audits are comprehensive, covering various areas such as policies, procedures, technical controls, and physical security. They identify gaps in security controls and provide recommendations for improving overall security. Security audits typically involve reviewing documentation, conducting interviews, and performing technical assessments. They are usually performed on a regular basis (annually or biannually) or as mandated by compliance regulations.
    
- **Penetration Tests**, on the other hand, simulate real-world attacks to identify and exploit vulnerabilities in systems, networks, or applications. The focus is on technical weaknesses and how attackers might exploit them. Penetration tests are specific to the systems or applications in question, using tools and techniques to breach systems and assess defenses. These tests provide detailed vulnerability assessments and recommendations for mitigating risks. Penetration tests are performed as needed, such as after major system changes or periodically as part of compliance.
    
While security audits focus on compliance and broad security evaluations, penetration tests are more technical and vulnerability-centric. Both can be performed sequentially or potentially combined, depending on the organization's security assessment needs.


### Sequential Approach

In the sequential approach, companies start with a **security audit** to assess their overall security posture, ensuring compliance with regulations and identifying weaknesses in policies, procedures, and controls. The audit offers a high-level view of how well security measures align with standards and highlights areas for improvement.

Once the audit is complete, a **penetration test** can be performed to focus on the technical aspects, evaluating the effectiveness of controls and identifying specific vulnerabilities. This method allows organizations to first address policy and procedural weaknesses before targeting technical flaws, ensuring a well-rounded security assessment.

**Advantages of the Sequential Approach:**

- Offers a comprehensive view, covering both policy and technical aspects.
- Helps identify gaps in both procedural and technical controls.
- Allows for prioritizing remediation based on audit findings before testing for vulnerabilities.

### Combined Approach

In the **combined approach**, organizations integrate security audits and penetration testing into a single, holistic security assessment. This allows for the evaluation of both procedural compliance and technical vulnerabilities simultaneously.

**Advantages of the Combined Approach:**

- Streamlines the assessment by incorporating both policy and technical evaluations.
- Provides a more complete security picture in one engagement.
- Can be more efficient and cost-effective, addressing compliance and technical risks together.

This method is particularly beneficial for organizations seeking a faster, consolidated assessment of their overall security posture.



### Example: Sequential Approach

A company uses a **sequential approach** to assess its security posture. First, the organization performs a security audit through an independent firm and uses the audit findings as the basis for its remediation efforts.

As part of this remediation plan, the company then hires a penetration tester to ensure the effectiveness of technical controls, particularly in achieving compliance with relevant standards such as PCI DSS.

**Audit Findings:**

- Inadequate encryption for sensitive data in transit.
- Weak network security controls and lack of sufficient traffic monitoring.
- Ineffective access control policies with excessive permissions.
- Outdated incident response procedures.

**Audit Recommendations:**

- Implement strong encryption for data in transit.
- Revise access control policies based on the principle of least privilege.
- Update and test incident response procedures regularly.

### Penetration Test

After addressing the audit findings, the company proceeds with a penetration test to verify whether the newly implemented security controls are effective.

**Phase 1: Planning and Preparation**

- Review network diagrams and compliance questionnaires to understand the current security measures and define the scope of the test, focusing on areas identified in the audit (e.g., network security, application vulnerabilities).
- Set up a testing schedule and inform stakeholders.

**Phase 2: Information Gathering and Reconnaissance**

- Gather information on security policies, encryption standards, access controls, and incident response procedures.
- Review the recent audit report to target areas of concern.

**Phase 3: Penetration Test Execution**

- Conduct network scans, vulnerability assessments, and attempts to exploit identified weaknesses.
- Assess the effectiveness of new encryption protocols and access controls.

**Phase 4: Findings and Recommendations**

- The penetration test reveals additional vulnerabilities:
    - An exposed administrative interface allowing unauthorized access.
    - SQL injection vulnerabilities in a customer-facing web application.

**Recommendations:**

- Secure the administrative interface with enhanced authentication and access controls.
- Patch the SQL injection vulnerabilities and review application security thoroughly.

### Summary of Sequential Approach

- **Security Audit Results:**
    - Identified compliance gaps and provided policy improvement recommendations.
- **Penetration Testing Results:**
    - Revealed specific technical vulnerabilities and offered targeted recommendations to mitigate them.

This approach allows the organization to first address high-level policy and compliance issues before diving into technical security vulnerabilities.


### GRC

Governance, Risk, and Compliance (GRC) is a framework that helps organizations align governance practices, manage risks, and ensure regulatory compliance. This integrated approach fosters transparency, accountability, and resilience in the face of complex regulatory challenges.

- **Governance** refers to the policies, procedures, and practices that guide an organization in achieving objectives, managing risks, and complying with regulations. This includes developing clear security policies, defining roles and responsibilities for security management, and establishing accountability mechanisms to ensure effective performance.
- **Risk management** focuses on identifying, assessing, and mitigating risks that could impact an organization’s operations or assets. It involves recognizing threats, evaluating their potential impact and likelihood, and implementing measures to reduce or eliminate risks.
- **Compliance** ensures that organizations follow relevant laws, regulations, and standards. This includes meeting legal obligations (e.g., GDPR, HIPAA), adhering to internal security policies, and conducting regular audits to verify compliance.
- **Importance of GRC in Penetration Testing:** Understanding GRC allows penetration testers to perform more comprehensive security assessments that align with an organization’s governance, risk, and compliance framework. This knowledge enhances reporting by framing findings within the organization's policies and regulations, and enables testers to provide strategic recommendations that strengthen the overall security posture.


## Frameworks-Standards-and-Guidelines

**Frameworks** provide structured, flexible approaches for implementing security practices across various industries.

- **NIST Cybersecurity Framework (CSF):** Offers guidelines for managing cybersecurity risk through five core functions: Identify, Protect, Detect, Respond, and Recover.
- **COBIT:** Focuses on aligning IT goals with business objectives, managing IT risks, and ensuring compliance.

**Standards** set specific, often mandatory, requirements for compliance, especially in regulated industries.

- **ISO/IEC 27001:** An international standard for managing and protecting sensitive information through information security management systems (ISMS).
- **PCI DSS:** Security standards for protecting payment card information, ensuring secure processing, and enforcing strong access controls.
- **HIPAA:** U.S. law mandating the protection of health data with privacy, security, and breach notification rules.
- **GDPR:** EU regulation governing data protection and privacy, outlining rights for individuals and obligations for organizations processing personal data.

**Guidelines** provide recommended best practices for improving security, typically voluntary.

- **CIS Controls:** Actionable best practices to strengthen cybersecurity, organized into categories such as basic, foundational, and organizational controls.



**From Audit to Pentest**

This section explains how security audits are conducted and how their results influence the scope and objectives of a penetration test, especially for organizations needing compliance with specific standards or regulations. The aim is to demonstrate how audit findings shape penetration testing strategies and adaptations to meet these requirements.

### Objectives:

- Establish a baseline security policy for Linux servers aligned with NIST SP 800-53 guidelines to ensure secure configuration and management.
- The policy will protect Linux servers from unauthorized access, vulnerabilities, and other security threats.
- It will define security requirements for configuring, maintaining, and monitoring Linux servers within the organization.

### Security Policy Development Process: Requirements Gathering

- **Access Control**: Define user account management, authentication methods, and privilege management.
- **Audit and Accountability**: Set logging requirements and procedures for reviewing logs.
- **Configuration Management**: Establish baseline configurations, update practices, and change management.
- **Identification and Authentication**: Enforce strong password policies and unique user identification.
- **System Integrity**: Implement malware protection, security monitoring, and vulnerability management.
- **Maintenance**: Control maintenance and use approved maintenance tools.

### Simple Security Policy for Linux Servers (Aligned with NIST SP 800-53)

**Phase 1 - Developing a Security Policy**

#### Access Control (AC)

- **AC-2, AC-5**: Only authorized personnel are granted access to Linux servers. Each user must have a unique account, and shared accounts are prohibited. Inactive accounts must be removed within 30 days.
- **IA-2, IA-5**: Enforce strong password policies (12 characters minimum) and use SSH key-based authentication. Password-based SSH access should be disabled, and 2FA should be required for privileged accounts.

#### Audit and Accountability (AU)

- **AU-2, AU-3**: Enable system logging using tools like rsyslog or journald to capture critical events.
- **AU-6, AU-7**: Regularly review logs for suspicious activity and retain them for at least 90 days.

#### Configuration Management (CM)

- **CM-2**: Maintain a secure baseline configuration for Linux servers, using tools like Ansible or Puppet to enforce configurations.
- **CM-3, CM-5**: Apply security patches and updates within 30 days of release.

#### Identification and Authentication (IA)

- **IA-5**: Enforce password complexity and expiration policies, and use password managers for secure password storage.
- **IA-4**: Ensure all users are uniquely identified.


### NIST SP 800-53

Security and Privacy Controls for Information Systems and Organizations

- Actual Publication (pdf): https://doi.org/10.6028/NIST.SP.800-53r5 
- Control Catalog Spreadsheet: Provides more information on the individual controls 
https://csrc.nist.gov/CSRC/media/Publications/sp/800-53/rev-5/final/documents/sp800-53r5-control-catalog.xlsx 

---

Lynis

Lynis is a open source tool for security auditing/hardening tools for Linux/Unix systems


https://cisofy.com/lynis/#download

Can downloads the tarball from Cisofy (https://cisofy.com/downloads/lynis/) 

```
wget https://downloads.cisofy.com/lynis/lynix....tar.gz
```

gzip

```
sudo apt-get install lynis
```


You can perform a scan on the local system by running the lynis binary then `audit system`.

```
lynis audit system
```

Will return an audit report including considerations of changes to make. Can reference the various of controls from Lynis's control site https://cisofy.com/lynis/controls/ 

```
lynis audit system --auditor "Name"
```

Remediate the vulnerabilities identified in the Lynis report and then document the remediation actions.


**Conduct Penetration Test**

**Objective:** Validate the effectiveness of remediation efforts by conducting a penetration test to ensure the Linux server is secure and compliant with the established security policy.

###### 1. Execution:

- **Network Scan:** Use Nmap to identify open ports and services.
- **Vulnerability Scanning:** Use Metasploit to detect and exploit vulnerabilities.
- **Web Application Testing:** If applicable, use Burp Suite to assess the security of web applications.

###### 2. Validating Remediation:

- **Compare Results:** Cross-check the initial audit findings with the penetration test results to confirm that vulnerabilities have been resolved.
- **Check for New Vulnerabilities:** Identify and address any new vulnerabilities introduced during the remediation phase.

###### 3. Reporting:

- **Executive Summary:** Summarize the key results and findings of the penetration test.
- **Methodology:** Outline the tools and techniques used during the test.
- **Findings:** Provide details on discovered vulnerabilities, including their severity and potential impact.
- **Recommendations:** Suggest further steps to enhance system security.

```
hydra -l root -P /usr/share/seclists/Passwords/xato-net-10-million-passwords.txt ssh://<remote IP> -t 2 -v
```