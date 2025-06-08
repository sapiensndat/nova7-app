import psycopg2
from psycopg2 import pool
import os

db_pool = psycopg2.pool.SimpleConnectionPool(1, 20, user="nova7", password="Disaster2024", host="localhost", port="5432", database="nova7_db")

def get_db_connection():
    if db_pool is None:
        raise Exception("Database pool not initialized")
    return db_pool.getconn()
