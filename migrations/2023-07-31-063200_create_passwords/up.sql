-- Your SQL goes here
CREATE TABLE user(
  id INTEGER NOT NULL PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE password(
  id INTEGER NOT NULL PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  username TEXT DEFAULT NULL,
  email TEXT DEFAULT NULL,
  key TEXT DEFAULT NULL,
  notes TEXT DEFAULT NULL,
  kdf_salt TEXT DEFAULT NULL,
  kdf_iterations INTEGER DEFAULT NULL,
  aes_nonce TEXT DEFAULT NULL,
  CONSTRAINT fk_user_password FOREIGN KEY (user_id) references User(id)
);
