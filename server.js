const express = require("express");
const { Pool } = require("pg");
const { newEnforcer } = require("casbin");
const PostgresAdapter =
  require("casbin-pg-adapter").default || require("casbin-pg-adapter");
const { expressjwt: jwt } = require("express-jwt");
const jwksRsa = require("jwks-rsa");

const KEYCLOAK_URL = "http://localhost:8082";
const REALM = "casbin-realm";
const DB_URI = "postgresql://postgres:thugs123@localhost:5432/casbin_db_multi_tenancy";

const pool = new Pool({ connectionString: DB_URI });

// 1. Keycloak JWT Authentication Middleware
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

// 2. Initialize Product Tables in PostgreSQL
async function initProductTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS organizations (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      created_by TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS invitations (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      target_domain TEXT NOT NULL,
      role TEXT NOT NULL,
      status TEXT DEFAULT 'pending'
    );
  `);
  console.log("Product tables (organizations, projects, invitations) ready.");
}

// 3. Seed Global Role Permission Templates into Casbin
async function seedRoleTemplates(enforcer) {
  // Always remove any orphaned g2 rules if they existed previously
  await pool.query("DELETE FROM casbin WHERE ptype = 'g2'");

  const existing = await enforcer.getPolicy();
  if (existing.length > 0) {
    console.log("Casbin role templates already seeded.");
    return;
  }

  console.log("Seeding role permission templates into Casbin...");

  // Admin: Full access to all org and project routes in their domain
  await enforcer.addPolicy("admin", "/api/*", "(GET)|(POST)|(PUT)|(DELETE)");

  // Editor: Can view org projects, and GET/POST/PUT articles in their project/org
  await enforcer.addPolicy("editor", "/api/orgs/:orgId/projects", "GET");
  await enforcer.addPolicy("editor", "/api/projects/:projectId/articles", "(GET)|(POST)");
  await enforcer.addPolicy("editor", "/api/projects/:projectId/articles/:id", "(GET)|(PUT)");

  // Viewer: Read-only access to projects and articles
  await enforcer.addPolicy("viewer", "/api/orgs/:orgId/projects", "GET");
  await enforcer.addPolicy("viewer", "/api/projects/:projectId/articles", "GET");
  await enforcer.addPolicy("viewer", "/api/projects/:projectId/articles/:id", "GET");

  console.log("Role templates seeded!");
}

// 4. Multi-Tenant Casbin Authorization Middleware
function authorizeTenant(enforcer) {
  return async (req, res, next) => {
    const user = req.auth?.preferred_username || "";
    // Clean trailing slashes so keyMatch2 always matches cleanly
    const fullPath = (req.baseUrl + req.path).replace(/\/+$/, "");
    const method = req.method;

    try {
      // Case A: Route is scoped to a Project (/api/projects/:projectId/...)
      if (req.params.projectId) {
        const projectId = req.params.projectId;
        const projDomain = `proj:${projectId}`;

        // Look up the project's parent organization in Postgres
        const projResult = await pool.query(
          "SELECT org_id FROM projects WHERE id = $1",
          [projectId]
        );
        if (projResult.rows.length === 0) {
          return res.status(404).json({ error: "Project not found" });
        }
        const orgDomain = `org:${projResult.rows[0].org_id}`;

        // Check if user has permission directly in the Project OR inherited from the parent Organization
        const allowedInProj = await enforcer.enforce(user, projDomain, fullPath, method);
        const allowedInOrg = await enforcer.enforce(user, orgDomain, fullPath, method);

        console.log(
          `[Authz Check] user=${user} | method=${method} | path=${fullPath} | proj(${projDomain})=${allowedInProj} | org(${orgDomain})=${allowedInOrg}`
        );

        if (!allowedInProj && !allowedInOrg) {
          return res.status(403).json({
            error: "forbidden",
            message: `User '${user}' lacks permission for ${method} ${fullPath} in ${projDomain} (or parent ${orgDomain})`,
          });
        }
        return next();
      }

      // Case B: Route is scoped to an Organization (/api/orgs/:orgId/...)
      if (req.params.orgId) {
        const orgDomain = `org:${req.params.orgId}`;
        const allowedInOrg = await enforcer.enforce(user, orgDomain, fullPath, method);

        console.log(
          `[Authz Check] user=${user} | method=${method} | path=${fullPath} | org(${orgDomain})=${allowedInOrg}`
        );

        if (!allowedInOrg) {
          return res.status(403).json({
            error: "forbidden",
            message: `User '${user}' lacks permission for ${method} ${fullPath} in ${orgDomain}`,
          });
        }
        return next();
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

async function main() {
  await initProductTables();

  const adapter = await PostgresAdapter.newAdapter({
    connectionString: DB_URI,
  });
  const enforcer = await newEnforcer("model.conf", adapter);
  await seedRoleTemplates(enforcer);

  const app = express();
  app.use(express.json());

  const api = express.Router();

  // =========================================================================
  // STEP A: SELF-SERVICE ROUTES (Any logged-in Keycloak user)
  // =========================================================================

  // 1. Create a new Organization (Creator becomes 'admin' of org:{id})
  api.post("/orgs", async (req, res, next) => {
    try {
      const user = req.auth.preferred_username;
      const { name } = req.body;

      const result = await pool.query(
        "INSERT INTO organizations (name, created_by) VALUES ($1, $2) RETURNING *",
        [name, user]
      );
      const org = result.rows[0];
      const orgDomain = `org:${org.id}`;

      await enforcer.addGroupingPolicy(user, "admin", orgDomain);

      res.status(201).json({
        message: `Organization '${name}' created. '${user}' is now admin of ${orgDomain}`,
        organization: org,
      });
    } catch (err) {
      next(err);
    }
  });

  // 2. Accept an Invitation
  api.post("/invitations/:inviteId/accept", async (req, res, next) => {
    try {
      const user = req.auth.preferred_username;
      const { inviteId } = req.params;

      const result = await pool.query(
        "SELECT * FROM invitations WHERE id = $1 AND username = $2 AND status = 'pending'",
        [inviteId, user]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "No pending invitation found for this user" });
      }

      const invite = result.rows[0];
      await pool.query("UPDATE invitations SET status = 'accepted' WHERE id = $1", [inviteId]);
      await enforcer.addGroupingPolicy(user, invite.role, invite.target_domain);

      res.status(200).json({
        message: `'${user}' accepted invite and is now '${invite.role}' in '${invite.target_domain}'`,
      });
    } catch (err) {
      next(err);
    }
  });

  // =========================================================================
  // STEP B: ORGANIZATION-SCOPED ROUTES
  // =========================================================================

  // 3. Create a Project inside an Organization
  api.post("/orgs/:orgId/projects", authorizeTenant(enforcer), async (req, res, next) => {
    try {
      const { orgId } = req.params;
      const { name } = req.body;

      const result = await pool.query(
        "INSERT INTO projects (org_id, name) VALUES ($1, $2) RETURNING *",
        [orgId, name]
      );

      res.status(201).json({
        message: `Project '${name}' created inside org:${orgId}`,
        project: result.rows[0],
      });
    } catch (err) {
      next(err);
    }
  });

  // 4. List Projects in an Organization
  api.get("/orgs/:orgId/projects", authorizeTenant(enforcer), async (req, res, next) => {
    try {
      const { orgId } = req.params;
      const result = await pool.query("SELECT * FROM projects WHERE org_id = $1", [orgId]);
      res.status(200).json({ projects: result.rows });
    } catch (err) {
      next(err);
    }
  });

  // 5. Invite a User to the Entire Organization
  api.post("/orgs/:orgId/invite", authorizeTenant(enforcer), async (req, res, next) => {
    try {
      const { orgId } = req.params;
      const { username, role } = req.body;

      const result = await pool.query(
        "INSERT INTO invitations (username, target_domain, role) VALUES ($1, $2, $3) RETURNING *",
        [username, `org:${orgId}`, role]
      );

      res.status(201).json({
        message: `Invited '${username}' as '${role}' to org:${orgId}`,
        invitation: result.rows[0],
      });
    } catch (err) {
      next(err);
    }
  });

  // =========================================================================
  // STEP C: PROJECT-SCOPED ROUTES
  // =========================================================================

  // 6. Invite a User to a Specific Project Only
  api.post("/projects/:projectId/invite", authorizeTenant(enforcer), async (req, res, next) => {
    try {
      const { projectId } = req.params;
      const { username, role } = req.body;

      const result = await pool.query(
        "INSERT INTO invitations (username, target_domain, role) VALUES ($1, $2, $3) RETURNING *",
        [username, `proj:${projectId}`, role]
      );

      res.status(201).json({
        message: `Invited '${username}' as '${role}' to proj:${projectId}`,
        invitation: result.rows[0],
      });
    } catch (err) {
      next(err);
    }
  });

  // 7. Project Articles CRUD (GET, POST, PUT, DELETE)
  api.get("/projects/:projectId/articles", authorizeTenant(enforcer), (req, res) => {
    res.status(200).json({ projectId: req.params.projectId, articles: ["Sample Project Article"] });
  });

  api.post("/projects/:projectId/articles", authorizeTenant(enforcer), (req, res) => {
    res.status(201).json({ projectId: req.params.projectId, created: true, by: req.auth.preferred_username });
  });

  api.put("/projects/:projectId/articles/:id", authorizeTenant(enforcer), (req, res) => {
    res.status(200).json({ projectId: req.params.projectId, updated: req.params.id, by: req.auth.preferred_username });
  });

  api.delete("/projects/:projectId/articles/:id", authorizeTenant(enforcer), (req, res) => {
    res.status(200).json({ projectId: req.params.projectId, deleted: req.params.id, by: req.auth.preferred_username });
  });

  // Mount all routes behind Keycloak JWT Authentication
  app.use("/api", authenticateJwt, api);

  app.use((err, req, res, next) => {
    if (err.name === "UnauthorizedError") {
      return res.status(401).json({ error: "unauthorized", details: err.message });
    }
    console.error(err);
    res.status(500).json({ error: "internal_error", details: err.message });
  });

  app.listen(8080, () =>
    console.log("Multi-Tenant Express Server running on :8080 (Using 'g' only)")
  );
}

main();