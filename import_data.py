"""
Import script to load RISK-0003_09 Excel data into the database
Usage: python import_data.py path/to/RISK-0003_09.xlsx
"""
import sys
import os
import pandas as pd
from app import app, db, Asset, StrideCategory, SeverityLevel, ExploitRiskLevel, RiskRating, Control, RiskAssessment

def import_excel_data(filepath):
    """Import risk assessment data from Excel file"""
    
    print(f"Loading Excel file: {filepath}")
    
    # Read all sheets
    xl = pd.ExcelFile(filepath)
    df_risks = pd.read_excel(xl, 'RiskAssessment-Detailed')
    df_controls = pd.read_excel(xl, 'ControlMeasures')
    
    print(f"Found {len(df_risks)} risk items and {len(df_controls)} control measures")
    
    with app.app_context():
        # Initialize lookup tables if empty
        if StrideCategory.query.count() == 0:
            init_lookup_tables()
        
        # Import Assets
        print("Importing assets...")
        assets_imported = 0
        for asset_name in df_risks['THREAT MODEL ASSET'].unique():
            if pd.notna(asset_name):
                existing = Asset.query.filter_by(name=asset_name.strip()).first()
                if not existing:
                    # Determine asset type based on name
                    asset_type = 'Component'
                    if ' to ' in asset_name:
                        asset_type = 'DataFlow'
                    elif any(x in asset_name.lower() for x in ['management', 'authentication', 'calculate']):
                        asset_type = 'Process'
                    
                    asset = Asset(name=asset_name.strip(), asset_type=asset_type)
                    db.session.add(asset)
                    assets_imported += 1
        db.session.commit()
        print(f"  Imported {assets_imported} new assets")
        
        # Import Controls
        print("Importing controls...")
        controls_imported = 0
        for _, row in df_controls.iterrows():
            control_id = row.get('Control Measure')
            if pd.notna(control_id):
                control_id = str(control_id).strip()
                existing = Control.query.get(control_id)
                if not existing:
                    control = Control(
                        id=control_id,
                        name=control_id,
                        description=str(row.get('Engineering Description', ''))[:1000] if pd.notna(row.get('Engineering Description')) else None,
                        category_tag=str(row.get('Tag', ''))[:10] if pd.notna(row.get('Tag')) else None
                    )
                    db.session.add(control)
                    controls_imported += 1
        db.session.commit()
        print(f"  Imported {controls_imported} new controls")
        
        # Import Risk Assessments
        print("Importing risk assessments...")
        risks_imported = 0
        
        # Create lookup dicts
        severity_map = {s.name: s.id for s in SeverityLevel.query.all()}
        exploit_map = {e.name: e.id for e in ExploitRiskLevel.query.all()}
        rating_map = {r.name: r.id for r in RiskRating.query.all()}
        asset_map = {a.name: a.id for a in Asset.query.all()}
        
        for _, row in df_risks.iterrows():
            assessment_num = row.get('#')
            if pd.isna(assessment_num):
                continue
            
            # Check if already exists
            existing = RiskAssessment.query.filter_by(assessment_number=int(assessment_num)).first()
            if existing:
                continue
            
            asset_name = row.get('THREAT MODEL ASSET', '').strip() if pd.notna(row.get('THREAT MODEL ASSET')) else None
            asset_id = asset_map.get(asset_name)
            
            if not asset_id:
                continue
            
            # Map values
            severity_name = str(row.get('SEVERITY', '')) if pd.notna(row.get('SEVERITY')) else None
            pre_exploit_name = str(row.get('PRE-MITIGATION EXPLOIT RISK', '')) if pd.notna(row.get('PRE-MITIGATION EXPLOIT RISK')) else None
            pre_rating_name = str(row.get('PRE-MITIGATION RISK RATING', '')) if pd.notna(row.get('PRE-MITIGATION RISK RATING')) else None
            
            # Get post-mitigation columns (handle newlines in column names)
            post_exploit_col = [c for c in df_risks.columns if 'POST-MITIGATION EXPLOIT RISK' in c][0]
            post_rating_col = [c for c in df_risks.columns if 'POST-MITIGATION RISK RATING' in c][0]
            
            post_exploit_name = str(row.get(post_exploit_col, '')) if pd.notna(row.get(post_exploit_col)) else None
            post_rating_name = str(row.get(post_rating_col, '')) if pd.notna(row.get(post_rating_col)) else None
            
            risk = RiskAssessment(
                assessment_number=int(assessment_num),
                asset_id=asset_id,
                operation=str(row.get('OPERATION', ''))[:50] if pd.notna(row.get('OPERATION')) else None,
                platform=str(row.get('PLATFORM', ''))[:50] if pd.notna(row.get('PLATFORM')) else None,
                model_ref=str(row.get('Model  Ref#', ''))[:20] if pd.notna(row.get('Model  Ref#')) else None,
                stride_code=str(row.get('STRIDEL', ''))[:1] if pd.notna(row.get('STRIDEL')) else None,
                stride_description=str(row.get('STRIDEL Description', ''))[:500] if pd.notna(row.get('STRIDEL Description')) else None,
                finding_number=str(row.get('FINDING #', ''))[:20] if pd.notna(row.get('FINDING #')) else None,
                severity_id=severity_map.get(severity_name),
                pre_exploit_risk_id=exploit_map.get(pre_exploit_name),
                pre_risk_rating_id=rating_map.get(pre_rating_name),
                post_exploit_risk_id=exploit_map.get(post_exploit_name),
                post_risk_rating_id=rating_map.get(post_rating_name),
                control_ids=str(row.get('CONTROLS', ''))[:100] if pd.notna(row.get('CONTROLS')) else None,
                reference_docs=str(row.get('Reference Doc', ''))[:500] if pd.notna(row.get('Reference Doc')) else None,
                assessment_year=2025,
                review_status='pending'
            )
            db.session.add(risk)
            risks_imported += 1
            
            if risks_imported % 100 == 0:
                print(f"  Processed {risks_imported} risks...")
                db.session.commit()
        
        db.session.commit()
        print(f"  Imported {risks_imported} risk assessments")
        
        print("\n=== Import Complete ===")
        print(f"Total Assets: {Asset.query.count()}")
        print(f"Total Controls: {Control.query.count()}")
        print(f"Total Risks: {RiskAssessment.query.count()}")

def init_lookup_tables():
    """Initialize lookup tables with standard values"""
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
    print("Lookup tables initialized")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python import_data.py <path_to_excel_file>")
        print("Example: python import_data.py RISK-0003_09.xlsx")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    import_excel_data(filepath)
