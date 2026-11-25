import psycopg2


def main():
    connection = None

    try:
        connection = psycopg2.connect(
            dbname="cyber_threat_db",
            user="ybayrirem",
            host="/var/run/postgresql"
        )

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT current_database(), current_user, version();
            """)
            database, user, version = cursor.fetchone()

        print("PostgreSQL connection successful.")
        print(f"Database: {database}")
        print(f"User: {user}")
        print(f"Server: {version.splitlines()[0]}")

    except psycopg2.Error as error:
        print(f"Database connection failed: {error}")

    finally:
        if connection is not None:
            connection.close()
            print("Connection closed.")


if __name__ == "__main__":
    main()
