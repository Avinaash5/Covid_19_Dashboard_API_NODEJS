const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, "covid19IndiaPortal.db");
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

//Authenticate MiddleWare Function
const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "Secret_Token", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.username = payload.username;
        next();
      }
    });
  }
};

//User Register API
app.post("/users/", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(request.body.password, 10);
  const selectUserQuery = `SELECT * FROM user WHERE username = '${username}'`;
  const dbUser = await db.get(selectUserQuery);
  if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO 
        user (username, name, password, gender, location) 
      VALUES 
        (
          '${username}', 
          '${name}',
          '${hashedPassword}', 
          '${gender}',
          '${location}'
        )`;
    await db.run(createUserQuery);
    response.send(`User created successfully`);
  } else {
    response.status(400);
    response.send("User already exists");
  }
});

///LOGIN API1
app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = ` SELECT * FROM user WHERE username='${username}' ;`;
  const dbUser = await db.get(selectUserQuery);
  if (dbUser === undefined) {
    response.status(400);
    response.send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched == true) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(payload, "Secret_Token");
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  }
});

//GET ALL States API2
app.get("/states/", authenticateToken, async (request, response) => {
  const getAllStatesQuery = `SELECT state_id AS stateId,
  state_name AS stateName,
  population FROM state;`;
  const statesArray = await db.all(getAllStatesQuery);

  response.send(statesArray);
});

//API3 GET State with StateId
app.get("/states/:stateId/", authenticateToken, async (request, response) => {
  const { stateId } = request.params;
  const getStateQuery = `
    SELECT * FROM state WHERE state_id=${stateId};`;
  const dbResponse = await db.get(getStateQuery);
  const convertDbObjectToResponseObject = (dbResponse) => {
    return {
      stateId: dbResponse.state_id,
      stateName: dbResponse.state_name,
      population: dbResponse.population,
    };
  };

  response.send(convertDbObjectToResponseObject(dbResponse));
});

//API4 ADD District
app.post("/districts/", authenticateToken, async (request, response) => {
  const districtDetails = request.body;
  const {
    districtName,
    stateId,
    cases,
    cured,
    active,
    deaths,
  } = districtDetails;

  const addDistrict = `INSERT INTO district (district_name,state_id,cases,cured,active,deaths)
  VALUES('${districtName}',${stateId}, ${cases}, ${cured}, ${active}, ${deaths});
  `;
  await db.run(addDistrict);
  response.send("District Successfully Added");
});

//API5 GET District
app.get(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const getDistrictQuery = `
    SELECT * FROM district WHERE district_id=${districtId};`;
    const dbResponse = await db.get(getDistrictQuery);
    const convertDbObjectToResponseObject = (dbResponse) => {
      return {
        districtId: dbResponse.district_id,
        districtName: dbResponse.district_name,
        stateId: dbResponse.state_id,
        cases: dbResponse.cases,
        cured: dbResponse.cured,
        active: dbResponse.active,
        deaths: dbResponse.deaths,
      };
    };
    response.send(convertDbObjectToResponseObject(dbResponse));
  }
);

//API6 DELETE District
app.delete(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const deleteDistrictQuery = `
    DELETE FROM district WHERE district_id=${districtId};`;
    const dbResponse = await db.run(deleteDistrictQuery);
    response.send("District Removed");
  }
);

//API7 Update District Details
app.put(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const districtDetails = request.body;
    const {
      districtName,
      stateId,
      cases,
      cured,
      active,
      deaths,
    } = districtDetails;
    const updateDistrictQuery = `
        UPDATE district 
        SET 
            district_name='${districtName}',
            state_id=${stateId},
            cases=${cases},
            cured=${cured},
            active=${active},
           deaths=${deaths}
         WHERE district_id= ${districtId};`;
    await db.run(updateDistrictQuery);
    response.send("District Details Updated");
  }
);

//API8 GET STATS of the State
app.get(
  "/states/:stateId/stats",
  authenticateToken,
  async (request, response) => {
    const { stateId } = request.params;
    const getStatsOfStateQuery = `
    SELECT SUM(cases) AS totalCases,
    SUM(cured) AS totalCured,
    SUM(active) AS totalActive,
    SUM(deaths) AS totalDeaths 
    FROM district WHERE state_id=${stateId};`;
    const dbResponse = await db.get(getStatsOfStateQuery);
    response.send(dbResponse);
  }
);

module.exports = app;
