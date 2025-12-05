
from sqlalchemy import create_engine, text

def fix_schema():
    url = 'postgresql://postgres:postgres@localhost:5432/auditgh_kb'
    engine = create_engine(url)
    
    with engine.connect() as conn:
        print("Adding architecture columns to repositories...")
        try:
            conn.execute(text("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_report TEXT"))
            conn.execute(text("ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_diagram TEXT"))
            conn.commit()
            print("Columns added successfully.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    fix_schema()
