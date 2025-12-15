"""
Glooko Risk Assessment Tracker
Flask application for managing cybersecurity risk assessments
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///data/risk_assessment.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ============================================================
# BASIC AUTH CONFIGURATION
# ============================================================

# Set these in Railway environment variables
AUTH_USERNAME = os.environ.get('AUTH_USERNAME', 'glooko')
AUTH_PASSWORD = os.environ.get('AUTH_PASSWORD', 'risk2026')

def check_auth(username, password):
    """Check if username/password combination is valid"""
    return username == AUTH_USERNAME and password == AUTH_PASSWORD

def authenticate():
    """Send 401 response to enable basic auth"""
    return Response(
        'Access denied. Please provide valid credentials.', 401,
        {'WWW-Authenticate': 'Basic realm="Glooko Risk Assessment"'}
    )

def requires_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ============================================================
# HEALTH CHECK (No Auth Required)
# ============================================================

@app.route('/health')
def health_check():
    """Health check endpoint for Railway - no auth required"""
    return jsonify({'status': 'healthy', 'app': 'risk-assessment-tracker'}), 200

# Fix for Render's postgres:// vs postgresql://
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)

# ============================================================
# DATABASE MODELS
# ============================================================

class Asset(db.Model):
    __tablename__ = 'asset'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    asset_type = db.Column(db.String(50))  # Component, DataFlow, Process
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    risks = db.relationship('RiskAssessment', backref='asset', lazy=True)

class StrideCategory(db.Model):
    __tablename__ = 'stride_category'
    code = db.Column(db.String(1), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)

class SeverityLevel(db.Model):
    __tablename__ = 'severity_level'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    value = db.Column(db.Integer, nullable=False)

class ExploitRiskLevel(db.Model):
    __tablename__ = 'exploit_risk_level'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    value = db.Column(db.Integer, nullable=False)

class RiskRating(db.Model):
    __tablename__ = 'risk_rating'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    action_required = db.Column(db.Text)

class Control(db.Model):
    __tablename__ = 'control'
    id = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category_tag = db.Column(db.String(10))
    is_active = db.Column(db.Boolean, default=True)

class RiskAssessment(db.Model):
    __tablename__ = 'risk_assessment'
    id = db.Column(db.Integer, primary_key=True)
    assessment_number = db.Column(db.Integer)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    operation = db.Column(db.String(50))
    platform = db.Column(db.String(50))
    model_ref = db.Column(db.String(20))
    stride_code = db.Column(db.String(1), db.ForeignKey('stride_category.code'))
    stride_description = db.Column(db.Text)
    finding_number = db.Column(db.String(20))
    severity_id = db.Column(db.Integer, db.ForeignKey('severity_level.id'))
    pre_exploit_risk_id = db.Column(db.Integer, db.ForeignKey('exploit_risk_level.id'))
    pre_risk_rating_id = db.Column(db.Integer, db.ForeignKey('risk_rating.id'))
    post_exploit_risk_id = db.Column(db.Integer, db.ForeignKey('exploit_risk_level.id'))
    post_risk_rating_id = db.Column(db.Integer, db.ForeignKey('risk_rating.id'))
    control_ids = db.Column(db.Text)  # Comma-separated control IDs
    reference_docs = db.Column(db.Text)
    assessment_year = db.Column(db.Integer, default=2025)
    review_status = db.Column(db.String(20), default='pending')  # pending, reviewed, approved
    reviewed_by = db.Column(db.String(100))
    reviewed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    stride = db.relationship('StrideCategory', backref='risks')
    severity = db.relationship('SeverityLevel', backref='risks')
    pre_exploit_risk = db.relationship('ExploitRiskLevel', foreign_keys=[pre_exploit_risk_id])
    pre_risk_rating = db.relationship('RiskRating', foreign_keys=[pre_risk_rating_id])
    post_exploit_risk = db.relationship('ExploitRiskLevel', foreign_keys=[post_exploit_risk_id])
    post_risk_rating = db.relationship('RiskRating', foreign_keys=[post_risk_rating_id])

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk_assessment.id'))
    action = db.Column(db.String(50))  # created, updated, reviewed
    field_changed = db.Column(db.String(100))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    changed_by = db.Column(db.String(100))
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============================================================
# ROUTES
# ============================================================

@app.route('/')
@requires_auth
def dashboard():
    """Main dashboard with summary statistics"""
    total_risks = RiskAssessment.query.count()
    total_assets = Asset.query.count()
    total_controls = Control.query.count()
    
    # Risk rating distribution
    pending_review = RiskAssessment.query.filter_by(review_status='pending').count()
    reviewed = RiskAssessment.query.filter_by(review_status='reviewed').count()
    
    # Post-mitigation rating distribution
    rating_dist = db.session.query(
        RiskRating.name, db.func.count(RiskAssessment.id)
    ).join(RiskAssessment, RiskAssessment.post_risk_rating_id == RiskRating.id
    ).group_by(RiskRating.name).all()
    
    # STRIDE distribution
    stride_dist = db.session.query(
        StrideCategory.code, StrideCategory.name, db.func.count(RiskAssessment.id)
    ).join(RiskAssessment, RiskAssessment.stride_code == StrideCategory.code
    ).group_by(StrideCategory.code, StrideCategory.name).all()
    
    # Recent activity
    recent_updates = RiskAssessment.query.order_by(
        RiskAssessment.updated_at.desc()
    ).limit(10).all()
    
    return render_template('dashboard.html',
        total_risks=total_risks,
        total_assets=total_assets,
        total_controls=total_controls,
        pending_review=pending_review,
        reviewed=reviewed,
        rating_dist=rating_dist,
        stride_dist=stride_dist,
        recent_updates=recent_updates
    )

@app.route('/risks')
@requires_auth
def risk_list():
    """List all risk assessments with filtering"""
    # Get filter parameters
    asset_id = request.args.get('asset_id', type=int)
    stride_code = request.args.get('stride_code')
    rating_id = request.args.get('rating_id', type=int)
    status = request.args.get('status')
    search = request.args.get('search', '')
    
    query = RiskAssessment.query
    
    if asset_id:
        query = query.filter_by(asset_id=asset_id)
    if stride_code:
        query = query.filter_by(stride_code=stride_code)
    if rating_id:
        query = query.filter_by(post_risk_rating_id=rating_id)
    if status:
        query = query.filter_by(review_status=status)
    if search:
        query = query.filter(
            db.or_(
                RiskAssessment.stride_description.ilike(f'%{search}%'),
                RiskAssessment.finding_number.ilike(f'%{search}%')
            )
        )
    
    risks = query.order_by(RiskAssessment.assessment_number).all()
    
    # Get filter options
    assets = Asset.query.order_by(Asset.name).all()
    stride_categories = StrideCategory.query.all()
    ratings = RiskRating.query.all()
    
    return render_template('risks.html',
        risks=risks,
        assets=assets,
        stride_categories=stride_categories,
        ratings=ratings,
        filters={
            'asset_id': asset_id,
            'stride_code': stride_code,
            'rating_id': rating_id,
            'status': status,
            'search': search
        }
    )

@app.route('/risks/<int:risk_id>')
@requires_auth
def risk_detail(risk_id):
    """View and edit a single risk assessment"""
    risk = RiskAssessment.query.get_or_404(risk_id)
    exploit_levels = ExploitRiskLevel.query.all()
    ratings = RiskRating.query.all()
    controls = Control.query.filter_by(is_active=True).order_by(Control.id).all()
    audit_logs = AuditLog.query.filter_by(risk_id=risk_id).order_by(AuditLog.changed_at.desc()).all()
    
    return render_template('risk_detail.html',
        risk=risk,
        exploit_levels=exploit_levels,
        ratings=ratings,
        controls=controls,
        audit_logs=audit_logs
    )

@app.route('/risks/<int:risk_id>/update', methods=['POST'])
@requires_auth
def risk_update(risk_id):
    """Update a risk assessment"""
    risk = RiskAssessment.query.get_or_404(risk_id)
    
    # Track changes for audit log
    changes = []
    
    # Update post-mitigation exploit risk
    new_exploit = request.form.get('post_exploit_risk_id', type=int)
    if new_exploit and new_exploit != risk.post_exploit_risk_id:
        old_val = risk.post_exploit_risk.name if risk.post_exploit_risk else None
        new_level = ExploitRiskLevel.query.get(new_exploit)
        changes.append(('post_exploit_risk', old_val, new_level.name if new_level else None))
        risk.post_exploit_risk_id = new_exploit
    
    # Update post-mitigation risk rating
    new_rating = request.form.get('post_risk_rating_id', type=int)
    if new_rating and new_rating != risk.post_risk_rating_id:
        old_val = risk.post_risk_rating.name if risk.post_risk_rating else None
        new_rat = RiskRating.query.get(new_rating)
        changes.append(('post_risk_rating', old_val, new_rat.name if new_rat else None))
        risk.post_risk_rating_id = new_rating
    
    # Update notes
    new_notes = request.form.get('notes', '')
    if new_notes != risk.notes:
        changes.append(('notes', risk.notes, new_notes))
        risk.notes = new_notes
    
    # Update review status
    new_status = request.form.get('review_status')
    if new_status and new_status != risk.review_status:
        changes.append(('review_status', risk.review_status, new_status))
        risk.review_status = new_status
        if new_status in ['reviewed', 'approved']:
            risk.reviewed_at = datetime.utcnow()
            risk.reviewed_by = request.form.get('reviewed_by', 'Unknown')
    
    # Update year
    risk.assessment_year = 2026
    
    # Save audit logs
    for field, old_val, new_val in changes:
        log = AuditLog(
            risk_id=risk_id,
            action='updated',
            field_changed=field,
            old_value=str(old_val) if old_val else None,
            new_value=str(new_val) if new_val else None,
            changed_by=request.form.get('reviewed_by', 'Unknown')
        )
        db.session.add(log)
    
    db.session.commit()
    flash('Risk assessment updated successfully', 'success')
    return redirect(url_for('risk_detail', risk_id=risk_id))

@app.route('/assets')
@requires_auth
def asset_list():
    """List all assets"""
    assets = Asset.query.order_by(Asset.name).all()
    
    # Get risk counts per asset
    asset_stats = db.session.query(
        Asset.id,
        db.func.count(RiskAssessment.id).label('risk_count')
    ).outerjoin(RiskAssessment).group_by(Asset.id).all()
    
    stats_dict = {s[0]: s[1] for s in asset_stats}
    
    return render_template('assets.html', assets=assets, stats=stats_dict)

@app.route('/controls')
@requires_auth
def control_list():
    """List all controls"""
    controls = Control.query.order_by(Control.id).all()
    return render_template('controls.html', controls=controls)

@app.route('/export/excel')
@requires_auth
def export_excel():
    """Export risk assessment to Excel"""
    # This would generate the Excel file
    flash('Excel export functionality - implement with openpyxl', 'info')
    return redirect(url_for('dashboard'))

@app.route('/api/stats')
@requires_auth
def api_stats():
    """API endpoint for dashboard statistics"""
    total_risks = RiskAssessment.query.count()
    pending = RiskAssessment.query.filter_by(review_status='pending').count()
    reviewed = RiskAssessment.query.filter_by(review_status='reviewed').count()
    
    return jsonify({
        'total_risks': total_risks,
        'pending_review': pending,
        'reviewed': reviewed,
        'progress_percent': round((reviewed / total_risks * 100) if total_risks > 0 else 0, 1)
    })

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """Initialize database with lookup tables"""
    with app.app_context():
        db.create_all()
        
        # Only seed if tables are empty
        if StrideCategory.query.count() == 0:
            # STRIDE-L Categories
            stride_data = [
                ('S', 'Spoofing', 'Attacker assumes identity of another user'),
                ('T', 'Tampering', 'Attacker changes data without authorization'),
                ('R', 'Repudiation', 'Attacker denies performing an action'),
                ('I', 'Information Disclosure', 'Attacker accesses unauthorized information'),
                ('D', 'Denial of Service', 'Attacker disrupts system availability'),
                ('E', 'Elevation of Privilege', 'Attacker gains unauthorized privileges'),
                ('L', 'Lateral Movement', 'Attacker moves between systems/networks'),
            ]
            for code, name, desc in stride_data:
                db.session.add(StrideCategory(code=code, name=name, description=desc))
            
            # Severity Levels
            for name, value in [('2 - Minor', 2), ('3 - Serious', 3), ('4 - CRITICAL', 4)]:
                db.session.add(SeverityLevel(name=name, value=value))
            
            # Exploit Risk Levels
            for name, value in [('1 - Low', 1), ('3 - Medium', 3), ('5 - High', 5)]:
                db.session.add(ExploitRiskLevel(name=name, value=value))
            
            # Risk Ratings
            ratings = [
                ('Acceptable', 'Organization can accept residual risk'),
                ('Mitigation Desirable', 'Organization MAY accept residual risk, but mitigation is recommended'),
                ('Remediation Required', 'Organization may NOT accept residual risk; remediation is required'),
            ]
            for name, action in ratings:
                db.session.add(RiskRating(name=name, action_required=action))
            
            db.session.commit()
            print("Database initialized with lookup tables")

# ============================================================
# INITIALIZE DATABASE ON STARTUP
# ============================================================

# This runs when gunicorn imports the app (not just when running directly)
with app.app_context():
    # Ensure data directory exists for SQLite
    os.makedirs('data', exist_ok=True)
    try:
        init_db()
        print("Database initialization complete")
    except Exception as e:
        print(f"Database initialization error: {e}")

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')