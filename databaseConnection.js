require('dotenv').config();
const { MongoClient } = require("mongodb");

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority`;

const client = new MongoClient(atlasURI);

async function connectToDatabase() {
    try {
        await client.connect();
        console.log("✅ MongoDB connected successfully");
        return client.db(mongodb_database); 
    } catch (err) {
        console.error("❌ MongoDB connection failed:", err);
        process.exit(1);
    }
}

module.exports = { connectToDatabase };
