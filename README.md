# 🔒 Glooko Risk Assessment Tracker

A lightweight web application for managing the 2026 Cybersecurity Risk Assessment (RISK-0003_10).

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-Internal-red)

---

## Features

- 📊 **Dashboard** - Visual summary of assessment progress
- 📋 **Risk Register** - Browse, filter, and search 778 risk items
- ✏️ **Edit Assessments** - Update post-mitigation ratings for 2026
- 🏢 **Asset Browser** - View risks by 32 threat model assets
- 🛡️ **Control Library** - Review 92 control measures
- 📈 **Audit Trail** - Track all changes with timestamps
- 📤 **Export** - Generate Excel/Word deliverables

---

## Quick Start (Local)

```bash
# 1. Clone/copy the app
cd risk-assessment-app

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Mac/Linux
# venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Import 2025 data
python import_data.py path/to/RISK-0003_09.xlsx

# 5. Run the app
python app.py

# 6. Open browser
# http://localhost:5000
```

---

## Deployment Options

| Platform | Guide | Setup Time | Cost |
|----------|-------|------------|------|
| 🚂 **Railway** | [railway/README.md](railway/README.md) | 5 min | Free |
| 🎨 **Render** | [render/README.md](render/README.md) | 5 min | Free |
| 💻 **Local Mac** | See Quick Start above | 2 min | $0 |

---

## Project Structure

```
risk-assessment-app/
├── app.py                  # Main Flask application
├── import_data.py          # Excel data import script
├── requirements.txt        # Python dependencies
├── Procfile               # Process definition
├── templates/             # HTML templates
│   ├── base.html          # Base layout
│   ├── dashboard.html     # Main dashboard
│   ├── risks.html         # Risk list view
│   ├── risk_detail.html   # Risk edit form
│   ├── assets.html        # Asset browser
│   └── controls.html      # Control library
├── railway/               # Railway deployment config
│   ├── railway.toml
│   └── README.md
├── render/                # Render deployment config
│   ├── render.yaml
│   └── README.md
└── data/                  # SQLite database (local only)
    └── risk_assessment.db
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11 + Flask 3.0 |
| Database | SQLite (local) / PostgreSQL (cloud) |
| ORM | SQLAlchemy 2.0 |
| Frontend | Bootstrap 5 + HTMX |
| Charts | Chart.js |
| Server | Gunicorn |

---

## Database Schema

```
┌─────────────────┐     ┌──────────────────┐
│     Asset       │────<│  RiskAssessment  │
├─────────────────┤     ├──────────────────┤
│ id              │     │ id               │
│ name            │     │ asset_id (FK)    │
│ asset_type      │     │ stride_code      │
└─────────────────┘     │ severity_id      │
                        │ pre_risk_rating  │
┌─────────────────┐     │ post_risk_rating │
│    Control      │     │ review_status    │
├─────────────────┤     └──────────────────┘
│ id              │              │
│ name            │              │
│ description     │     ┌────────┴─────────┐
└─────────────────┘     │    AuditLog      │
                        ├──────────────────┤
                        │ risk_id (FK)     │
                        │ field_changed    │
                        │ old_value        │
                        │ new_value        │
                        └──────────────────┘
```

---

## Usage

### Importing Data

```bash
# Import from Excel file
python import_data.py RISK-0003_09.xlsx

# Output:
# Loading Excel file: RISK-0003_09.xlsx
# Found 778 risk items and 155 control measures
# Importing assets... 32 new assets
# Importing controls... 92 new controls
# Importing risk assessments... 778 risk assessments
# === Import Complete ===
```

### Updating Assessments

1. Navigate to **Risks** in the nav bar
2. Filter by status = "Pending"
3. Click a risk item to open detail view
4. Update:
   - Post-Mitigation Exploit Risk (2026)
   - Post-Mitigation Risk Rating (2026)
   - Review Status
   - Notes
5. Click **Save Changes**

### Exporting Data

- Click **Export to Excel** on the dashboard
- Generates updated Risk and Control Matrix for RISK-0003_10

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///data/risk_assessment.db` |
| `SECRET_KEY` | Flask session secret | `dev-secret-key` |
| `PORT` | Server port | `5000` |
| `FLASK_DEBUG` | Enable debug mode | `false` |

---

## Security Considerations

⚠️ **This app handles sensitive cybersecurity risk data**

- Do not expose to public internet without authentication
- Use HTTPS in production (Railway/Render provide this)
- Regularly backup the database
- Check with Security Officer before cloud deployment

---

## License

**Internal Use Only** - Glooko, Inc.

---

## Support

For questions about this tool, contact the Risk Assessment project team.

---

*Built for the 2026 Cybersecurity Risk Assessment Update (RISK-0003_10)*
