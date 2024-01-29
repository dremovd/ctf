relevant_code1 = """
var session Session
result := db.Where("cookie = ?", cookieValue).Find(&session)
if result.Error != nil {
    c.HTML(http.StatusOK, template, gin.H{})
    return
}
result = db.Create(&Record{
    User:    user,
    Pass:    password,
    Site:    address,
    UserRef: session.User,
})
""".strip()

description1 = """
No check if cookie is valid or not, only react if no cookie set. 
If cookie value is set from outside, anybody can use this method to create a record with it's own user and password and an empty UserRef.
In this case, empty UserRef is used for login data effectively results in creating a user with name same as user already registered and arbitrary password.
Effectively, this gives an attacker the ability to get access to any user's account data.
""".strip()

code_fix1 = """
# Check if cookie is valid
- if result.Error != nil {
+ if result.Error != nil || result.RowsAffected == 0 {
""".strip()

example1 = {
    "relevant_code": relevant_code1,
    "name": "Missing cookie validation",
    "description": description1,
    "severity": "High",
    "code_fix": code_fix1,
}

relevant_code2 = """
result := db.Order("Id asc").Find(&saved, places)
...

linq.From(route).ZipT(linq.From(saved), func(placeId PlaceId, data PlaceData) PlaceInfo {
    return toPlaceInfo(userId, placeId, data)
}).ForEachT(func(item PlaceInfo) {
    enc.Encode(item)
})
""".strip()

description2 = """
Route could have NaNs which leads to ZipT dissynchronisation and access to other user data.
""".strip()

code_fix2 = """
// Add check for nan values in placeId
placeId, e := PlaceIdFromString(item, EncryptionKey)
if e != nil {
    err = e
}

+ if math.IsNaN(placeId.Lat) || math.IsNaN(placeId.Long) {
+ 	err = fmt.Errorf(ErrorInvalidPlace)
+ }
"""

example2 = {
    "relevant_code": relevant_code2,
    "name": "ZipT could have NaNs",
    "description": description2,
    "severity": "Medium",
    "code_fix": code_fix2,
}

relevant_code3 = """
$hash = password_hash($private_key_pem, PASSWORD_BCRYPT, ["cost" => 6]);
""".strip()

description3 = """
Using the PASSWORD_BCRYPT as the algorithm, will result in the password parameter being truncated to a maximum length of 72 bytes.
In this case, effectively there are only 5 possible unique hashes for all private keys because of private_key_pem similar starting bytes. 
This leads to a possibility of authentication for any user.
"""

code_fix3 = """
# Use DEFAULT algorithm for hashing
- $hash = password_hash($private_key_pem, PASSWORD_BCRYPT, ["cost" => 6]);
+ $hash = password_hash($private_key_pem, PASSWORD_DEFAULT, ["cost" => 6]);
"""

example3 = {
    "relevant_code": relevant_code3,
    "name": "Private key is truncated",
    "description": description3,
    "severity": "High",
    "code_fix": code_fix3,
}

relevant_code4 = """
public class AuthMiddleware
{
    ...
    private readonly List<string> _blacklist = new()
    {
        "/api/login",
        "/api/register",
    };
...
public async Task InvokeAsync(HttpContext context, ApplicationDbContext db)
    {
        if (_blacklist.Any(context.Request.FullPath().Contains))
        {
            await _next(context);
            return;
        }
""".strip()

description4 = """
Auth Middleware is checking for /api/login or /api/register to skip user verification. Strings are matched against the entirety of the request path and query, not just query. Unauthenticated users can download license files directly.
For example, if an URL have a query '?a=/api/register', 
""".strip()

code_fix4 = """
# Check only for path
- if (_blacklist.Any(context.Request.FullPath().Contains))
+ if (_blacklist.Any(context.Request.Path.Value.StartsWith))
""".strip()

example4 = {
    "relevant_code": relevant_code4,
    "name": "Unauthenticated users can access any path",
    "description": description4,
    "severity": "High",
    "code_fix": code_fix4,
}

examples = [example1, example2, example3, example4]
