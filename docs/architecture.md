# PrivacyGuard AI Architecture

```text
                         +----------------------+
                         |   React Web Client   |
                         | Dashboard / Analyzer |
                         +----------+-----------+
                                    |
                                  REST
                                    |
                         +----------v-----------+
                         |      Flask API       |
                         | JWT / RBAC boundary  |
                         +----------+-----------+
                                    |
               +--------------------+--------------------+
               |                    |                    |
       +-------v------+     +-------v------+     +-------v------+
       | Input Parser |     | Hybrid PII   |     | Audit / DB   |
       | TXT/PDF/DOCX |     | Detector     |     | SQLAlchemy   |
       +--------------+     +-------+------+     +--------------+
                                    |
                         +----------v-----------+
                         | Privacy Risk Engine  |
                         | entity + combination |
                         | + uniqueness/prox.   |
                         +----------+-----------+
                                    |
                         +----------v-----------+
                         | Adaptive Policy      |
                         | mask / replace /     |
                         | pseudo / remove      |
                         +----------+-----------+
                                    |
                         +----------v-----------+
                         | Output Auditor       |
                         | re-scan for leakage |
                         +----------+-----------+
                                    |
                         +----------v-----------+
                         | Report / Dashboard   |
                         +----------------------+
```

## Research contribution boundary

External open-source engines provide baseline detection/anonymization. PrivacyGuard's original application layer focuses on combined privacy-risk assessment, adaptive policy selection, output auditing, auditability and evaluation hooks.
