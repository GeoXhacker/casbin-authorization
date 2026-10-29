const express = require("express");
const { newEnforcer } = require("casbin");
// const { PostgresAdapter } = require("casbin-pg-adapter");
const PostgresAdapter = require("casbin-pg-adapter").default || require("casbin-pg-adapter");
const { expressjwt: jwt } = require("express-jwt");
const jwksRsa = require("jwks-rsa");

const KEYCLOAK_URL = "http://localhost:8082";
const REALM = "casbin-realm";

// Update with your local Postgres credentials
const DB_URI = "postgresql://postgres:thugs123@localhost:5432/casbin_db";

// 1. Authentication Middleware (Keycloak JWT)
const authenticateJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`,
  }),
  issuer: `${KEYCLOAK_URL}/realms/${REALM}`,
  algorithms: ["RS256"],
});

// 2. Authorization Middleware (Casbin)
function authorize(enforcer) {
  return async (req, res, next) => {
    const user = req.auth?.preferred_username || "";

    try {
      const allowed = await enforcer.enforce(
        user,
        req.baseUrl + req.path,
        req.method
      );
      if (!allowed) {
        return res.status(403).json({
          error: "forbidden",
          message: `User '${user}' is not allowed to ${req.method} on ${req.baseUrl + req.path}`,
        });
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

// 3. Seed Initial Policies into Postgres (if DB is empty)
async function seedPolicies(enforcer) {
  const existingPolicies = await enforcer.getPolicy();
  if (existingPolicies.length > 0) {
    console.log("Database already contains policies. Skipping seed.");
    return;
  }

  console.log("Seeding initial policies into PostgreSQL...");

  // Add permission rules (p)
  await enforcer.addPolicy("admin", "/api/*", "(GET)|(POST)|(PUT)|(DELETE)");
  await enforcer.addPolicy("editor", "/api/articles", "(GET)|(POST)");
  await enforcer.addPolicy("editor", "/api/articles/:id", "(GET)|(PUT)");
  await enforcer.addPolicy("viewer", "/api/articles", "GET");
  await enforcer.addPolicy("viewer", "/api/articles/:id", "GET");

  // Add user-role assignments (g)
  await enforcer.addGroupingPolicy("alice", "admin");
  await enforcer.addGroupingPolicy("bob", "editor");
  await enforcer.addGroupingPolicy("carol", "viewer");

  console.log("Seeding complete!");
}

async function main() {
  // Connect Casbin to PostgreSQL
  const adapter = await PostgresAdapter.newAdapter({
    connectionString: DB_URI,
  });

  // Pass the adapter instead of "policy.csv"
  const enforcer = await newEnforcer("model.conf", adapter);

  // Seed default rules on first run
  await seedPolicies(enforcer);

  const app = express();
  app.use(express.json()); // Needed to parse JSON bodies

  const api = express.Router();

  // Article Routes
  api.get("/articles", (req, res) => res.json({ articles: [] }));
  api.post("/articles", (req, res) => res.status(201).json({ created: true }));
  api.put("/articles/:id", (req, res) => res.json({ updated: req.params.id }));
  api.delete("/articles/:id", (req, res) => res.json({ deleted: req.params.id }));

  // Dynamic Role Management Route (Only 'admin' can call POST /api/*)
  api.post("/roles", async (req, res) => {
    const { user, role } = req.body;
    await enforcer.addRoleForUser(user, role);
    res.status(201).json({ message: `Assigned role '${role}' to '${user}' in PostgreSQL` });
  });

  app.use("/api", authenticateJwt, authorize(enforcer), api);

  app.use((err, req, res, next) => {
    if (err.name === "UnauthorizedError") {
      return res.status(401).json({ error: "unauthorized", details: err.message });
    }
    next(err);
  });

  app.listen(8080, () => console.log("Express listening on :8080 with Postgres Adapter"));
}

main();