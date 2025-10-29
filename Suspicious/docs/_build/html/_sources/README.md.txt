# Suspicious

Phishing is a widespread form of social engineering attack aimed at stealing sensitive data such as login credentials, payment information, or personal details. 
Attackers impersonate trusted entities to deceive victims into opening emails, messages, or links that may lead to malware installation, ransomware, or data exposure. 
These attacks have become increasingly sophisticated, making detection and prevention critical.

**Suspicious** is a web application designed to support this need by providing automated analysis of potentially malicious content. 
It allows users to submit and investigate different types of data, including:

- Emails (MSG /EML format)
- Files (PDF, DOC/DOCX, XLS/XLSX, EXE, MSI, HTML, ZIP, etc.)
- IP addresses
- URLs
- Hashes

### How It Works

#### Mail submission

1. Users send a suspicious email as an attachment to the dedicated address (e.g., `suspicious@test.com`).
2. The system splits the submission into individual components (headers, body, attachments, links, etc.).  
3. Each component is analyzed using **Cortex analyzers** (external APIs and rulesets such as YARA).  
4. Results are aggregated, scored, and classified.  
5. The frontend provides users with access to reports, detailed analysis, and final conclusions. 
6. Using the configured SMTP server it sends back a quick report / answer to the User

#### Web form

1. Users goes to the web platform and uses the `Submit an Item` page to send an Item to analyze (File, IP, Url, Hash)
2. If the Item is an MSG or EML File, the system splits the submission into individual components (headers, body, attachments, links, etc.).  
3. Each component is analyzed using **Cortex analyzers** (external APIs and rulesets such as YARA).  
4. Results are aggregated, scored, and classified.  
5. The frontend provides users with access to reports, detailed analysis, and final conclusions.  

### Classification
Based on the analysis score, submissions are categorized into four levels:

- **Dangerous** – Cannot be opened; content must not be trusted.  
- **Suspicious** – Should not be opened; content is risky.  
- **Inconclusive** – Can be opened, but content should not be trusted.  
- **Safe** – Can be opened; content is considered trustworthy.  

## Architecture & Workflow

**Suspicious** is designed as a modular and containerized web application that can be deployed easily using Docker.  
The core application is built with **Django (Python)**, ensuring flexibility, maintainability, and straightforward setup.  

A database is mandatory for the application to run, while additional services can be integrated to enhance its capabilities.  

### Core Requirements

- **Database** (MySQL, MariaDB, or PostgreSQL) – Stores submissions, reports, and analysis results.  
- **Elasticsearch** – Provides fast and efficient search capabilities across stored data.  
- **[StrangeBee's Cortex](https://github.com/TheHive-Project/Cortex)** – Executes analyzer jobs for processing emails, files, IP addresses, and URLs.  
- **MinIO S3** – Handles object storage for uploaded files and extracted artifacts. 

## Installation

To install Suspicious, please review our [CONFIG.md](CONFIG.md) and [SETUP.md](SETUP.md)

## Screenshots

### Home page

<img width="1845" height="1072" alt="image" src="https://github.com/user-attachments/assets/51a1a6cb-d58b-4175-996f-dc6cf2fc8345" />

### User Submissions page

<img width="1844" height="1053" alt="image" src="https://github.com/user-attachments/assets/23c61439-78d4-4aa3-aa54-db8fd21a028f" />

### Submit page

<img width="1748" height="982" alt="image" src="https://github.com/user-attachments/assets/949d789b-b034-44e7-9a97-57361853c0a0" />

### Dashboard Classic

<img width="1844" height="1067" alt="image" src="https://github.com/user-attachments/assets/a9b6200a-c6b5-4114-b77d-c36f3214a6af" />

### Dashboard Phishing Campaign

<img width="1843" height="1066" alt="image" src="https://github.com/user-attachments/assets/afabf61c-ba64-4b55-8343-e4df2c3061a0" />

### Settings

<img width="1843" height="1067" alt="image" src="https://github.com/user-attachments/assets/67548827-ca17-47f4-9d10-3f4ed8e75b4f" />

### Profile

<img width="1845" height="1067" alt="image" src="https://github.com/user-attachments/assets/9c57dc60-0956-4822-89e0-7eef8551efa4" />

### Admin Page

<img width="1846" height="1062" alt="image" src="https://github.com/user-attachments/assets/c32f4b66-e22e-4336-b65e-312a79aaa223" />

## Contributing

Contributions are welcome! If you'd like to contribute to Suspicious, please review our [CONTRIBUTING.md](CONTRIBUTING.md) guidelines for information on our development process, coding standards, and how to submit pull requests.

## License

Suspicious is licensed under the GNU AFFERO GENERAL PUBLIC License. For more details, see the [LICENSE](LICENSE) file.

## Contact

For questions, feedback, or support, please open an issue on GitHub
