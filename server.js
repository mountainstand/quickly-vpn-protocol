const express = require('express');
const mongoose = require('mongoose');
const { spawn, exec, execFile, execSync } = require('child_process');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const util = require('util');
const cron = require('node-cron');
const app = express();
const jwt = require('jsonwebtoken');
const speedTest = require("speedtest-net");
const dotenv = require('dotenv').config();
const readFile = util.promisify(fs.readFile);
const appendFile = util.promisify(fs.appendFile);
const access = util.promisify(fs.access);
const unlink = util.promisify(fs.unlink);
const writeFile = util.promisify(fs.writeFile);
const PORT = process.env.PORT || 3000;
const BASEURL = `http://${process.env.REMOTE_ADDRESS}:${PORT}`;



const crypto = require("crypto")

const User = require("./models/User");
const authController = require('./controllers/authController')
const protect = require('./utils/authmiddleware');
const server_publickey = process.env.SERVER_PUBLIC_KEY;

app.use("/peers", express.static(path.join(__dirname, "peers")));
app.use(express.json())
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB using Mongoose
mongoose.connect(`${process.env.MONGO_URI}`)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB:', err));

// ejs file integrate
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

const IpSecretCertPath = '/etc/ipsec.d/cacerts/ca-cert.pem';
const IpSecretPath = '/etc/ipsec.secrets';

// Directory where user configurations will be stored
const CONFIG_DIR = __dirname + '/peers'; //'/etc/wireguard/peers'; // Update with your desired directory path
const WG_INTERFACE = 'wg0'; // Update with your WireGuard interface name
const VPN_SUBNET = '10.0.0.0/8'; // Update with your desired VPN subnet

const OPENVPN_DIR = "/etc/easy-rsa"; // Path to OpenVPN setup
const UPLOADS_DIR = path.join(__dirname, "uploads");
const TA_FILE_DIR = "/etc/openvpn/"
// Ensure uploads folder exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}

const generateRandomPassword = (length = 12) => {
  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const numbers = "0123456789";
  const specialChars = "@%&*_+";

  const allChars = uppercase + lowercase + numbers + specialChars;

  let password = [
    uppercase[Math.floor(Math.random() * uppercase.length)],
    lowercase[Math.floor(Math.random() * lowercase.length)],
    numbers[Math.floor(Math.random() * numbers.length)],
    specialChars[Math.floor(Math.random() * specialChars.length)]
  ];

  while (password.length < length) {
    password.push(allChars[Math.floor(Math.random() * allChars.length)]);
  }

  return password.sort(() => Math.random() - 0.5).join('');
};

// Auth apis

// SocialSignin

app.post("/api/auth/social-signin", authController.socialLogin);

// register api
app.post("/api/auth/register", authController.register);

// login
app.post("/api/auth/login", authController.login);

// Forget Password
app.post("/api/auth/forget-password", authController.forgotpassword);


app.get("/api/auth/reset-password/:token", authController.resetpasswordform);

app.post("/api/auth/reset-password/:token", authController.resetpassword);

// get profile details
app.get("/api/fetch-userdetail", protect, authController.userDetail);

app.delete("/api/auth/delete-user", protect, authController.deleteUser);

app.post("/api/ikev2", async (req, res) => {
  try {
    const { udid } = req.body;
    const serverIp = `${process.env.REMOTE_ADDRESS}`;//req.ip;
    const newpassword = await generateRandomPassword();

    if (!udid) {
      return res.status(400).json({ error: "udid is required" });
    }
    const existUser = await User.findOne({ udid: udid });
    const ikevCertData = await readFile(IpSecretCertPath, 'utf8');

    if (existUser) {
      if (existUser.isIkev2 == 'yes') {
        await User.updateOne({ udid: udid }, { $set: { lastConnection: new Date() } });
        return res.status(200).json({
          success: true,
          message: "Success",
          data: {
            user: existUser,
            serverIp: serverIp,
            ikevCertData: ikevCertData
          }
        });
      } else {
        const password = !existUser?.openvpnPassword ? newpassword : existUser?.openvpnPassword;
        const newEntry = `\n${udid} : EAP "${password}"`;
        await appendFile(IpSecretPath, newEntry);
        await User.updateOne({ udid: udid }, { $set: { openvpnPassword: password, lastConnection: new Date(), isIkev2: 'yes' } });
        return res.status(200).json({
          success: true,
          message: "Success",
          data: {
            user: existUser,
            serverIp: serverIp,
            ikevCertData: ikevCertData
          }
        });
      }
    }

    const newEntry = `\n${udid} : EAP "${newpassword}"`;
    await appendFile(IpSecretPath, newEntry);

    const user = new User({
      udid: udid,
      openvpnPassword: newpassword,
      lastConnection: new Date(),
      isIkev2: 'yes'
    });
    await user.save();

    return res.status(201).json({
      success: true,
      message: "Success",
      data: {
        user: user,
        serverIp: serverIp,
        ikevCertData: ikevCertData
      }
    });

  } catch (error) {
    console.error("Unexpected error", error);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.post("/api/open-vpn", async (req, res) => {
  try {
    const { udid } = req.body;
    const serverIp = `${process.env.REMOTE_ADDRESS}`;//req.ip;

    if (!udid) {
      return res.status(400).json({ error: "udid is required" });
    }

    const newpassword = await generateRandomPassword();
    const existUser = await User.findOne({ udid: udid });
    const password = !(existUser?.openvpnPassword) ? newpassword : existUser?.openvpnPassword;
    if (existUser) {
      const ovpnFilePath = path.join(UPLOADS_DIR, `${udid}.ovpn`);
      if (fs.existsSync(ovpnFilePath)) {
        const vpnData = await readFile(ovpnFilePath, 'utf8');
        if (vpnData) {
          await User.updateOne({ udid: udid }, { $set: { lastConnection: new Date() } });
          return res.status(200).json({
            success: true,
            message: "Success",
            data: {
              user: existUser,
              serverIp: serverIp,
              ovpn: vpnData
            }
          });
        } else {
          await User.updateOne({ udid: udid }, { $set: { lastConnection: new Date(), openvpnPassword: password } });
        }
      }
    }

    const genReqProcess = execFile("/usr/bin/expect", ["-c", `
      spawn ./easyrsa gen-req ${udid} nopass
      expect "Enter PEM pass phrase:"
      send "${password}\r"
      expect "Verifying - Enter PEM pass phrase:"
      send "${password}\r"
      expect eof
    `], { cwd: OPENVPN_DIR }, (error, stdout, stderr) => {
      try {
        if (error) {
          console.error("Error generating request:", stderr);
          return res.status(500).json({ error: stderr });
        }
        console.log("Output:", stdout);
      } catch (err) {
        console.error("Unexpected error:", err);
      }
    });

    genReqProcess.on("close", (code) => {
      try {
        if (code !== 0) {
          return res.status(500).json({ error: `gen-req failed with exit code ${code}` });
        }

        console.log("Signing the client request...");

        const signReqProcess = execFile("/usr/bin/expect", ["-c", `
          spawn ./easyrsa sign-req client ${udid}
          expect "Confirm request details:"
          send "yes\r"
          expect "${OPENVPN_DIR}/pki/private/ca.key:"
          send "Admin@123\r"
          expect eof
        `], { cwd: OPENVPN_DIR }, (signError, signStdout, signStderr) => {
          try {
            if (signError) {
              console.error("Error signing request:", signStderr);
              return res.status(500).json({ error: signStderr });
            }
            console.log("Client request signed successfully.");
          } catch (err) {
            console.error("Unexpected error");
          }
        });


        signReqProcess.on("close", async (signCode) => {
          try {
            if (signCode !== 0) {
              return res.status(500).json({ error: `sign-req failed with exit code ${signCode}` });
            }

            const caPath = path.join(OPENVPN_DIR, "/pki/ca.crt");
            const certPath = path.join(OPENVPN_DIR, `pki/issued/${udid}.crt`);
            const keyPath = path.join(OPENVPN_DIR, `pki/private/${udid}.key`);
            const tlsAuthPath = path.join(TA_FILE_DIR, "ta.key");

            if (![caPath, certPath, keyPath, tlsAuthPath].every(fs.existsSync)) {
              console.log("hlo", caPath);
              return res.status(500).json({ error: "Required VPN files are missing" });
            }

            const ca = fs.readFileSync(caPath, "utf8");
            const cert = fs.readFileSync(certPath, "utf8");
            const key = fs.readFileSync(keyPath, "utf8");
            const tlsAuth = fs.readFileSync(tlsAuthPath, "utf8");

            // Extract only the certificate content
            const certMatch = cert.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
            const extractedCert = certMatch ? certMatch[0].trim() : '';

            let ovpnConfig =
              `client
dev tun
proto tcp
remote ${process.env.REMOTE_ADDRESS} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
allow-compression no
verb 3
<tls-auth>
${tlsAuth}
</tls-auth>
<ca>
${ca}
</ca>
<cert>
${extractedCert}
</cert>
<key>
${key}
</key>`.trim();

            const ovpnFilePath = path.join(UPLOADS_DIR, `${udid}.ovpn`);
            fs.writeFileSync(ovpnFilePath, ovpnConfig);

            if (!existUser) {
              const user = new User({
                udid: udid,
                openvpnPassword: password,
                lastConnection: new Date(),
              });
              await user.save();

              return res.status(201).json({
                success: true,
                message: "Success",
                data: {
                  user: user,
                  serverIp: serverIp,
                  ovpn: ovpnConfig
                }
              });

            }

            return res.status(200).json({
              success: true,
              message: "Success",
              data: {
                user: existUser,
                serverIp: serverIp,
                ovpn: ovpnConfig
              }
            });

          } catch (err) {
            console.error("Unexpected error");

            return res.status(500).json({
              success: false,
              message: err,
              data: {}
            });
          }
        });
      } catch (err) {
        console.error("Unexpected error");
        return res.status(500).json({
          success: false,
          message: err,
          data: {}
        });
      }
    });



  } catch (error) {
    console.error("Unexpected error", error);
    if (!res.headersSent) {
      return res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.get("/api/speedtest", async (req, res) => {
  try {
    res.setHeader("Content-Type", "application/json");

    // Run the speed test using await
    const data = await speedTest({
      acceptLicense: true,
      acceptGdpr: true,
      timeout: 120000,
    });
    res.status(200).json({
      success: true,
      data: {
        download: (data.download.bandwidth / 125000).toFixed(2) + "Mbps", // Convert to Mbps
        upload: (data.upload.bandwidth / 125000).toFixed(2) + "Mbps",  // Convert to Mbps
        ping: data.ping.latency, // ms
        isp: data.isp,
        server: {
          name: data.server.name,
          location: `${data.server.location}, ${data.server.country}`,
          // distance: data.server.distance.toFixed(2) + " km",
        }
      },
      message: "success",
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Speed test failed. Try again later." });
  }
});

// Endpoint to connect a user
app.post('/api/connect', async (req, res) => {
  try {
    console.log(req.body)
  const udid = req.body.udid;
  const endpoint = `${process.env.REMOTE_ADDRESS}:51820`;
  const dns = "8.8.8.8";
  const allowedips = "0.0.0.0/0"
  // Generate key pair for the user

  const existUser = await User.findOne({ udid: udid, wireguardIpAddress: { $exists: true } });

  if (existUser) {
    await User.updateOne({ udid: udid }, { $set: { lastConnection: new Date() } });
    return res.status(200).json({
      success: true,
      config: `${BASEURL}/peers/${udid}/configfile.conf`,
      user: existUser,
      dns: dns,
      allowedips: allowedips,
      endpoint: endpoint,
      server_publickey: server_publickey
    });
  }

  const keyPair = await generateWireGuardKeyPair(udid);

  if (!keyPair) {
    return res.status(200).json({ success: false, message: "Unable to generate Key pair" });
  }
  //const keyPair = generateKeyPair(udid);
  const publicKey = keyPair.publicKey;
  const privateKey = keyPair.privateKey;
  const ipAddress = await getNextIPAddress(udid);

  createClientConfig(server_publickey, privateKey, ipAddress, udid);
  addWireGuardPeer(publicKey, ipAddress, udid);

  const user = new User({
    udid: udid,
    publicKey: publicKey,
    privateKey: privateKey,
    wireguardIpAddress: ipAddress,
    lastConnection: new Date()
  });
  await user.save();

  if (user) {
    return res.status(200).json({
      success: true,
      config: `${BASEURL}/peers/${udid}/configfile.conf`,
      user: user,
      dns: dns,
      allowedips: allowedips,
      endpoint: endpoint,
      server_publickey: server_publickey
    });
  }

  return res.status(200).json({ success: false, message: "Unable to create details" });

  } catch (error) {
    console.error(`Error connecting user: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Start the server

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// genrate random token
function generateUniqueToken(length = 32) {
  return crypto.randomBytes(length).toString('hex'); // Converts to hex format
}

function generateWireGuardKeyPair(udid) {
  try {

    var folderPath = CONFIG_DIR + '/' + udid;

    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath);
    }
    // if (!path.existsSync(folderPath)) {
    //     fs.mkdirSync(folderPath);
    // }

    // Step 1: Generate Private Key
    const privateKeyCommand = 'wg genkey';
    const privateKey = execSync(privateKeyCommand, { encoding: 'utf-8' }).trim();

    // Step 2: Generate Public Key from Private Key
    const publicKeyCommand = `echo ${privateKey} | wg pubkey`;
    const publicKey = execSync(publicKeyCommand, { encoding: 'utf-8' }).trim();

    fs.writeFileSync(path.join(folderPath, 'private_key'), privateKey);
    fs.writeFileSync(path.join(folderPath, 'public_key'), publicKey);

    // return {
    //     privateKey,
    //     publicKey,
    // };
    return { publicKey: publicKey.toString().trim(), privateKey: privateKey.toString().trim() };
  } catch (error) {
    console.error('Error generating WireGuard key pair:', error.message);
    return null;
  }
}

// Function to generate a random public/private key pair and create a folder for the UDID
function generateKeyPair(udid) {
  try {
    // Create folder for the UDID if it doesn't exist

    var folderPath = CONFIG_DIR + '/' + udid;
    if (!path.existsSync(folderPath)) {
      fs.mkdirSync(folderPath);
    }

    // Generate key pair
    const privateKey = execSync('wg genkey');

    console.log(privateKey)
    const publicKey = execSync(`echo "${privateKey}" | wg pubkey`);

    // Write key pair to files within the folder
    fs.writeFileSync(path.join(folderPath, 'private_key'), privateKey);
    fs.writeFileSync(path.join(folderPath, 'public_key'), publicKey);

    return { publicKey: publicKey.toString().trim(), privateKey: privateKey.toString().trim() };
  } catch (error) {
    console.error(`Error generating key pair: ${error.message}`);
    return null;
  }
}

// Function to get the next available IP address
function getNextIPAddress() {
  try {

    const assignedIPs = fs.readdirSync(CONFIG_DIR)
      //.map(file => fs.readFileSync(path.join(CONFIG_DIR, file), 'utf8'))
      .filter(content => content.includes('Address'))
      .map(content => content.split('=')[1].trim());

    let randomIP;
    do {
      randomIP = `10.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}/32`;
    } while (assignedIPs.includes(randomIP));

    return randomIP;
  } catch (error) {
    console.log(error)
    return null
  }
}

function setWireGuardPublicKey(peerName, publicKey) {
  try {
    const configPath = '/etc/wireguard/your-interface.conf';  // Replace with your actual configuration file path

    // Read the existing configuration
    const configFile = fs.readFileSync(configPath, 'utf-8');

    // Modify the configuration to set the public key for the specified peer
    const updatedConfig = configFile.replace(
      new RegExp(`^\\s*PublicKey\\s*=.*?${peerName}`, 'm'),
      `PublicKey = ${publicKey}`
    );

    // Write the updated configuration back to the file
    fs.writeFileSync(configPath, updatedConfig);

    console.log(`WireGuard public key set for ${peerName} successfully.`);
  } catch (error) {
    console.log('Error setting WireGuard public key:', error.message);
  }
}

// Function to add peer to WireGuard configuration
function addWireGuardPeer(publicKey, ipAddress, udid) {
  execSync(`wg set ${WG_INTERFACE} peer ${publicKey} allowed-ips ${ipAddress}`);
}

// Function to create client configuration file
function createClientConfig(server_publickey, privateKey, ipAddress, udid) {
  try {
    // Validate required parameters
    if (!server_publickey || !privateKey || !ipAddress || !udid) {
      console.warn("Warning: Missing parameters in createClientConfig.");
      return null; // Return null instead of crashing
    }

    // Ensure CONFIG_DIR exists
    if (!fs.existsSync(CONFIG_DIR)) {
      fs.mkdirSync(CONFIG_DIR, { recursive: true });
    }

    // Ensure the directory for this UDID exists
    const userDir = path.join(CONFIG_DIR, udid);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }

    // Generate the client config
    const clientConfig = `
      [Interface]
      PrivateKey = ${privateKey}
      Address = ${ipAddress}
      DNS = 8.8.8.8
      [Peer]
      PublicKey = ${server_publickey}
      AllowedIPs = 0.0.0.0/0, ::/0
      Endpoint = ${process.env.REMOTE_ADDRESS}:51820
      `;

    // Write the config file
    const filePath = path.join(userDir, "configfile.conf");
    fs.writeFileSync(filePath, clientConfig.trim());

    console.log(`Client config created successfully at: ${filePath}`);
    return filePath;
  } catch (error) {
    console.log("Error creating client config:", error.message);
    return null; // Instead of crashing, return null and let the application continue
  }
}

// Schedule task to delete unused keys and IPs after 30 days
cron.schedule('0 0 * * *', async () => {
  try {
    const thresholdDate = moment().subtract(30, 'days').toDate();
    const inactiveUsers = await User.find({ lastConnection: { $lt: thresholdDate } });

    inactiveUsers.length > 0 && inactiveUsers.forEach(async (user) => {
      // Delete key pair and IP configuration
      //const userConfigFile = path.join(CONFIG_DIR, `${user.udid}/${user.publicKey}.conf`);
      if (user.publicKey) {
        execSync(`wg set ${WG_INTERFACE} peer ${user.publicKey} remove`);
        const directoryPath = `${CONFIG_DIR}/${user.udid}`;
        if (fs.existsSync(directoryPath)) {
          const files = fs.readdirSync(directoryPath);

          files.forEach((file) => {
            const filePath = path.join(directoryPath, file);
            if (fs.statSync(filePath).isDirectory()) {
              removeDirectory(filePath);
            } else {
              fs.unlinkSync(filePath);
            }
          });

          fs.rmdirSync(directoryPath);
          console.log(`Directory '${directoryPath}' removed successfully.`);
        } else {
          console.log(`Directory '${directoryPath}' does not exist.`);
        }
      }

      if (user.openvpnPassword) {
        const ovpnPath = `${UPLOADS_DIR}/${user.udid}.ovpn`;
        const certPath = path.join(OPENVPN_DIR, `pki/issued/${user.udid}.crt`);
        const keyPath = path.join(OPENVPN_DIR, `pki/private/${user.udid}.key`);

        const deleteOperations = [ovpnPath, certPath, keyPath].map(async (filePath) => {
          try {
            await access(filePath, fs.constants.F_OK); // Check if file exists
            await unlink(filePath); // Delete the file
            console.log(` Deleted: ${filePath}`);
          } catch (error) {
            console.log(`⚠️ Skipped (File not found): ${filePath}`);
          }
        });

        await Promise.all(deleteOperations);
      }

      if (user.isIkev2 == 'yes') {
        const fileContent = await readFile(IpSecretPath, 'utf-8');
        const lineToRemove = `${user.udid} : EAP "${user.openvpnPassword}"`;

        // Remove the specific line
        const updatedContent = fileContent
          .split('\n')
          .filter(line => !line.includes(lineToRemove)) // Remove lines that contain 'lineToRemove'
          .join('\n');

        // Write the updated content back to the file
        await writeFile(IpSecretPath, updatedContent, 'utf-8');
        console.log(`Remove ${lineToRemove} `);
      }

      //await fs.promises.unlink(userConfigFile); // Delete client configuration file
      await User.deleteOne({ _id: user._id }); // Delete user from database

      console.log(`User Deleted`);
    });


  } catch (error) {
    console.log(`Error deleting inactive users: ${error.message}`);
  }
});

// Function to free up IP address
async function freeIPAddress(ipAddress) {
  try {
    // Find the user with the specified IP address in the database
    const user = await User.findOne({ ipAddress });

    if (user) {
      // Update the user's IP address status to available
      user.ipAddress = null; // Assuming you mark the IP address as null or update it to indicate availability
      await user.save();
      console.log(`IP address ${ipAddress} freed up successfully.`);
    } else {
      console.error(`Error: No user found with IP address ${ipAddress}.`);
    }
  } catch (error) {
    console.error(`Error freeing up IP address: ${error.message}`);
  }
}
