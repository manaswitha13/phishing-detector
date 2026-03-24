const BASE_URL = "http://localhost:5000";
let authToken = "";

// Signup
async function signup() {
    const username = username.value;
    const password = password.value;

    const res = await fetch(BASE_URL + "/signup", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({username,password})
    });

    const data = await res.json();
    alert(data.message);
}

// Login
async function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const res = await fetch(BASE_URL + "/login", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({username,password})
    });

    const data = await res.json();

    if(res.status===200){
        authToken = data.token;
        alert("Login success");

        document.getElementById("auth").style.display="none";
        document.getElementById("app").style.display="block";
    } else {
        alert(data.message);
    }
}

// Logout
function logout(){
    authToken="";
    location.reload();
}

// Scan
async function scan(){
    const url = document.getElementById("urlInput").value;

    const res = await fetch(BASE_URL + "/scan",{
        method:"POST",
        headers:{
            "Content-Type":"application/json",
            "Authorization":authToken
        },
        body: JSON.stringify({url})
    });

    const data = await res.json();

    document.getElementById("result").innerHTML =
        `<h2>${data.label}</h2><p>${data.score}</p>`;
}

// History
async function loadHistory(){
    const res = await fetch(BASE_URL+"/history",{
        headers:{"Authorization":authToken}
    });

    const data = await res.json();

    document.getElementById("history").innerHTML =
        data.map(i=>`<li>${i.url} - ${i.result.label}</li>`).join("");

    let s=0, su=0, p=0;

    data.forEach(i=>{
        if(i.result.label==="Safe") s++;
        else if(i.result.label==="Suspicious") su++;
        else p++;
    });

    new Chart(document.getElementById("chart"),{
        type:"pie",
        data:{
            labels:["Safe","Suspicious","Phishing"],
            datasets:[{data:[s,su,p]}]
        }
    });
}