import sqlite3
from datetime import datetime
import config

class DBHandler:
    def __init__(self, db_path=config.DB_PATH):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        """Creates the files table if it doesn't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                filename TEXT PRIMARY KEY,
                uploaded_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def add_file(self, filename: str):
        """Adds a new file record to the registry."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT OR REPLACE INTO files (filename, uploaded_at) VALUES (?, ?)", (filename, timestamp))
        self.conn.commit()

    def remove_file(self, filename: str):
        """Removes a file record from the registry."""
        self.cursor.execute("DELETE FROM files WHERE filename = ?", (filename,))
        self.conn.commit()

    def get_files(self) -> list:
        """Returns a list of all stored filenames."""
        self.cursor.execute("SELECT filename FROM files ORDER BY uploaded_at DESC")
        return [row[0] for row in self.cursor.fetchall()]

    def close(self):
        self.conn.close()