# Finance
*This is one of the CS50 projects that I did in 4 days.*  

This finance website can help users look up, buy, sell stocks and deposit or withdraw money.

This program is meant for practice in pset9 of CS50x. One of the course from Harvard University.

**Backend: Python with Flask, sqlite3 for database and werkzeug security for hashing password**

**Frontend: Html, CSS, JS and Ajax**

You can use my IEX API which is: pk_b8c99080a20644f892fe286076da91bf but you can have your own token by:

1. Visit https://iexcloud.io/cloud-login#/register/
2. Select the “Individual” account type, then enter your name, email address, and a password, and click “Create account”.
3. Once registered, scroll down to “Get started for free” and click “Select Start plan” to choose the free plan.
4. Once you’ve confirmed your account via a confirmation email, visit https://iexcloud.io/console/tokens.
5. Copy the key that appears under the Token column (it should begin with pk_). This is your API token.

To initialize the website, in the terminal window, execute:
```
$ export API_KEY=value
```
where value is that (pasted) value, without any space immediately before or after the =. 

Then:
```
$ export FLASK_APP=app.py
$ export FLASK_DEBUG=1 
```
<sub>You can skip FLASK_DEBUG if you do not want the debug mode</sub>

# My result video:


https://user-images.githubusercontent.com/81196027/195263098-a5797894-2f0a-42d2-a01c-b6e8ef74805c.mp4

