# Spring Security Configuration without WebSecurityConfigurerAdapter

This project is used to explain how authentication architecture works in Spring Security. It is actually copy of `spring-security-authentication-scenario-5` project in the same repo. 
However, Spring Security deprecated WebSecurityConfigurerAdapter since 5.7. This repo removes `WebSecurityConfigurerAdapter` and use up-to-date configuration.

Please visit this blog post if you want to read.
https://backendstory.com/spring-security-authentication-architecture-explained-in-depth/

or you can visit this Youtube video if you prefer watching.
https://youtu.be/ElY3rjtukig

### How to run:
This project does not use any database, so you do not need to set up anything specific. Just run as it is.

**Method 1:** Right-click on the `SpringSecurityUpgrade.java` and then click `Run`.

**Method 2:** Run mvn `spring-boot:run` in your terminal.

### Why are all classes in one file?
I think it is easier to follow the flow when all of the classes are in the same file. It is just educational purpose, not a best practice to do.

### Endpoints:
There are two endpoints available in this project. One for fetching authentication token and one for accessing protected endpoint.

**Step 1:** You will need to use the following cURL to fetch the authentication token.
```console
curl --location --request POST 'http://localhost:8080/login' \
--header 'Content-Type: application/json' \
--data-raw '{
"username": "martin",
"password": "123"
}'
```

This request will give you a JWT token that will be used for authentication. An example of the response is below.
```console
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtYXJ0aW4iLCJpc3MiOiJiYWNrZW5kc3RvcnkuY29tIiwiaWF0IjoxNjYxNjcxNTM2LCJleHAiOjE2NjE2NzE1OTZ9.BKRX9eGNzfbqNJ6yNgZjgC6x2Y7aVcZyWM48bsxB9aE
```

**Step 2:** Then, you can hit `/hello` endpoint with the token you got from the cURL request above.
```console
curl --location --request GET 'http://localhost:8080/hello' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer <token-here>'
```

