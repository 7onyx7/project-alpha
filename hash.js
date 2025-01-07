const bcrypt = require("bcrypt");

const password = ""; // Replace with your desired password
(async () => {
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log("Hashed Password:", hashedPassword);
})();
