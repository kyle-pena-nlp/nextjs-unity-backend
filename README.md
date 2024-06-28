# install postgresql
brew install postgresql
# start postgres and it will now autostart when your machine starts
brew services start postgresql
# create a login for postgres.
psql -U postgres
CREATE DATABASE mydb;
CREATE USER myuser WITH PASSWORD 'mypassword';
GRANT ALL PRIVILEGES ON DATABASE mydb TO myuser;
# exists psql
\q

Put this in your .env:
DATABASE_URL="postgresql://myuser:mypassword@localhost:5432/mydb"
SECRET_KEY="your_secret_key"
PORT=3000

Start with: 
npx ts-node src/index.ts
