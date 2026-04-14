Repo for making tasks for proposal in Terminal Bench 3.0.

Easy Task:
For a task that an agent tool should be able to pass is just simply decoding a JWT and writing the claims to a file that will be verified.
Given the JWT and access to writing and running python code, an agent should easily be able
to use existing libraries to decode a well-formed JWT.

Hard Task:
For a task that an agent tool can fail, I propose having an agent forge a JWT for a vulnerable verifier. After some research, it seems that there exists “JWT Algorithm Confusion” where we can input the algorithm for our JWT token, which allows us to use symmetric cryptography and forge a key. I think in obfuscated code that allows the JWT to denote the algorithm in use “HS256” vs the private key crypto “RS256”, an agent might fail to realize this bug exists and make use of it.

I am thinking of a larger goal such as running a simple application that has this vulnerability and asking the agent to create a session with admin permissions and then make a given user an admin. This is then verified.

My idea here is that there is some exploit that exists for the adversary agent but is not told directly to the agent. This I think could fail for weaker models and possibly succeed for better ones. This exploit is obviously known so it might be harder, but through obfuscation I think it might become sufficiently possible to fail.

For the application, lets do a simple flask application:
/app/
  app.py           # routes: /login, /promote, /users
  auth.py          # vulnerable JWT verifier buried here
  db.json          # {"users": {"bob": {"role": "user"}, "admin": {"role": "admin"}}}
  requirements.txt
The /promote endpoint requires a valid admin JWT to elevate another user's role. The agent has to forge one to call it successfully. The test just checks db.json at the end. The agent shouldn't directly interface with the db.json, it must be obfuscated by the Flask application.
