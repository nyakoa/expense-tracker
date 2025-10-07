import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import Chart from "chartjs";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week in milliseconds
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PORT,
});
db.connect();

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

app.get("/", isLoggedIn, async (req, res) => {
  let income = 0;
  let expenses = 0;
  const response = await db.query(
    "SELECT * FROM expense_tracker WHERE user_id=$1",
    [req.user.id]
  );
  const transactions = response.rows;

  transactions.forEach((tx) => {
    if (tx.type === "income") {
      income += Number(tx.amount);
    } else if (tx.type === "expense") {
      expenses += Number(tx.amount);
    }
  });
  const balance = income - expenses;

  res.render("index.ejs", {
    transactions: transactions,
    totalIncome: income,
    totalExpenses: expenses,
    totalBalance: balance,
    user: req.user.username,
  });
});
app.get("/login", (req, res) => {
  res.render("login.ejs", {
    totalBalance: 0,
    totalExpenses: 0,
    totalIncome: 0,
  });
});
app.get("/register", (req, res) => {
  res.render("register.ejs", {
    totalBalance: 0,
    totalExpenses: 0,
    totalIncome: 0,
  });
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/transactions",
  passport.authenticate("google", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);
app.post("/add", (req, res) => {
  res.render("new.ejs");
});

app.post("/new", isLoggedIn, async (req, res) => {
  const date = req.body.date;
  const category = req.body.category;
  const type = req.body.type;
  const amount = req.body.amount;
  try {
    await db.query(
      "INSERT INTO expense_tracker (date,category,type,amount,user_id) VALUES ($1,$2,$3,$4,$5)",
      [date, category, type, amount, req.user.id]
    );
    res.redirect("/");
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.post("/delete", async (req, res) => {
  const deleteItemId = req.body.deleteItemId;
  await db.query("DELETE FROM expense_tracker WHERE id=$1", [deleteItemId]);
  res.redirect("/");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res, next) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query(
      "SELECT * FROM users WHERE username=$1",
      [email]
    );

    if (checkResult.rows.length > 0) {
      return res.redirect("/login");
    }

    const hash = await bcrypt.hash(password, saltRounds);

    const result = await db.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
      [email, hash]
    );

    const user = result.rows[0];

    req.login(user, (err) => {
      if (err) return next(err);
      res.redirect("/");
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

passport.use(
  "local",
  new Strategy(async function (username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE username=$1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.log("Error comparing password:", err);
          } else if (valid) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        });
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (error) {
      console.log(error);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/transactions",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, Profiler, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE username=$1", [
          Profiler.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username,password) VALUES($1,$2)",
            [Profiler.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (error) {
        console.log(error);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
