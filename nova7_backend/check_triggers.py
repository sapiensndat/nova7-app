from sqlalchemy import create_engine
from sqlalchemy.sql import text

# Database connection details
DATABASE_URI = "postgresql://nova7:Disaster2024@localhost:5432/nova7_db"

# Create engine
engine = create_engine(DATABASE_URI)

# Query for triggers on team_membership table
with engine.connect() as connection:
    result = connection.execute(text("""
        SELECT trigger_name, event_manipulation, event_object_table, action_statement
        FROM information_schema.triggers
        WHERE event_object_table = 'team_membership';
    """))
    triggers = result.fetchall()
    if triggers:
        print("Triggers found on team_membership table:")
        for trigger in triggers:
            print(f"Trigger: {trigger[0]}, Event: {trigger[1]}, Table: {trigger[2]}, Action: {trigger[3]}")
    else:
        print("No triggers found on team_membership table.")

