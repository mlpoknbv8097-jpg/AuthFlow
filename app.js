import express from "express";
import bcrypt from "bcrypt";
const app = express();

app.use(express.json());

const users = [];

app.post("/register", async (request, response) => {
  try {
    const { UserName, Email, Phone, Age, Password } = request.body;
    
    // Check if user already exists
    const FindUsers = users.find((data) => data.Email === Email);
    if (FindUsers) {
      response.status(400).send("This information already exists.");
      return;
    }
    
    // We only hash the password, NEVER the email (salt rounds: 10)
    const HashedPassword = await bcrypt.hash(Password, 10);
    
    users.push({
      UserName,
      Email, // Keep email as it is to find the user later
      Phone,
      Age,
      Password: HashedPassword,
    });
    
    response.status(201).send("The operation was completed successfully.");
  } catch (err) {
    response.status(500).send({ message: err.message });
  }
});

app.post("/login", async (request, response) => {
  try {
    const { Email, Password } = request.body;
    
    // 1. Find the user by their email first
    const user = users.find((data) => data.Email === Email);
    
    // If no user found with this email
    if (!user) {
      response.status(400).send("The information you entered is incorrect.");
      return;
    }
    
    // 2. Compare the password with the hashed password in the "database"
    const isPasswordCorrect = await bcrypt.compare(Password, user.Password);
    
    if (isPasswordCorrect) {
      response.status(200).send("Login successful!");
    } else {
      response.status(400).send("The information you entered is incorrect.");
    }
  } catch (err) {
    response.status(500).send({ message: err.message });
  }
});

app.listen(300, () => {
  console.log("Holle Mohamed Nasser Emam In Seriver!");
});
