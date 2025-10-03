# Suspicious

Suspicious is a powerful web application designed to help users submit and analyze various types of data—including emails, files, IP addresses, and URLs—to detect and investigate potentially malicious content. By leveraging external APIs through Cortex jobs and a modular processing workflow, Suspicious streamlines the analysis process with a user-friendly interface.

## Features

- **Multi-Data Analysis:** Analyze emails, files, IP addresses, and URLs.
- **Modular Workflow:** Process submissions through a dedicated pipeline that includes data fetching, processing, artifact extraction, and API-driven analysis.
- **Containerized Deployment:** Simplified setup and scalability with Docker and Docker Compose.
- **User & Admin Interfaces:**
  - **My Submissions:** Users can view the status and results of their past submissions.
  - **Submit an Item:** Easily submit new data for analysis.
  - **Investigation:** Administrators have access to monitor all submissions and validate analysis outcomes.
- **Dashboard:** Statistics and KPIs are easily readable.
- **Profiles:** Profiles to change preferences for each users and customize the interface.

## Architecture & Workflow

Suspicious is built using Django and uses a MariaDB database coupled with a MinIO bucket for storage. Its backend architecture emphasizes modularity and scalability

- **Email Reading:**
  An Email feeder is included, this feeder helps the suspicious app to retrieve emails. The process is simple, it reads from a mailbox and then upload the new email in a Bucket.

- **Email Workflow:**
  Suspicious incorporates a comprehensive email processing pipeline. The workflow involves:
  - **Reading:** The bucket is read to retrieve the new email and attachments.
  - **Processing:** Emails are processed for headers, attachments, and content using methods and various utilities that validate and analyze the email components.
  - **Artifact Extraction:** Extracted observables (e.g., attachments, URLs, IP addresses) are analyzed further by launching Cortex jobs.

- **Containerization & Deployment:**
  The entire application, including its job processing components, is containerized. This ensures consistent environments across development, testing, and production.

- **Cortex Integration:**
  As part of its modular design, Suspicious uses Cortex jobs to call different external APIs, analyze the submitted data, and return the results to the backend for further processing.

## Installation

To install Suspicious, please review our [CONFIG.md](CONFIG.md) and [SETUP.md](SETUP.md)

## Contributing

Contributions are welcome! If you'd like to contribute to Suspicious, please review our [CONTRIBUTING.md](CONTRIBUTING.md) guidelines for information on our development process, coding standards, and how to submit pull requests.

## License

Suspicious is licensed under the MIT License. For more details, see the [LICENSE](LICENSE) file.

## Contact

For questions, feedback, or support, please open an issue on GitHub
