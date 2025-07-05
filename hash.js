const bcrypt = require("bcrypt");
const logger = require("./logger");

const password = ""; // Replace with your desired password
(async () => {
  const hashedPassword = await bcrypt.hash(password, 10);
  logger.info("Hashed Password:", hashedPassword);
})();
