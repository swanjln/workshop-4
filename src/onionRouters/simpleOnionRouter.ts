import axios from "axios";
import express, { Request, Response } from "express";
import bodyParser from "body-parser";
import { generateRsaKeyPair, exportPubKey, rsaDecrypt, symDecrypt } from "../crypto";
import { exportPrvKey } from "../crypto";
import { Node } from "../registry/registry";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT, BASE_USER_PORT } from "../config";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());


  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  let rsaKeyPair = await generateRsaKeyPair();
  let pubKey = await exportPubKey(rsaKeyPair.publicKey);
  let privateKey = rsaKeyPair.privateKey;


  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req: Request, res: Response) => {
    res.status(200).json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req: Request, res: Response) => {
    res.status(200).json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req: Request, res: Response) => {
    res.status(200).json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.status(200).json({result: await exportPrvKey(privateKey)});
  });

  onionRouter.post("/message", async (req, res) => {
    const {message} = req.body;
    const decryptedKey = await rsaDecrypt(message.slice(0, 344), privateKey);
    const decryptedMessage = await symDecrypt(decryptedKey, message.slice(344));
  
    const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
    const remainingMessage = decryptedMessage.slice(10);
    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;
  
    // Check if the next destination is the final destination
    if (nextDestination === BASE_USER_PORT + 1) {
      // If it is, send the original message
      await axios.post(`http://localhost:${nextDestination}/message`, { message: "Hello World!" }, {
        headers: {
          "Content-Type": "application/json"
        }
      });
    } else {
      // If it's not, forward the remaining message
      await axios.post(`http://localhost:${nextDestination}/message`, { message: remainingMessage }, {
        headers: {
          "Content-Type": "application/json"
        }
      });
    }
  
    res.status(200).send("success");
  });

  // Register the node on the registry
  try {
    await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      nodeId: nodeId,
      pubKey: pubKey,
    });
    console.log(`Node ${nodeId} registered successfully.`);
  } catch (error) {
    // @ts-ignore
    console.error(`Error registering node ${nodeId}:`, error.message);
  }

  onionRouter.get("/hello", (req, res) => {
    res.send("Hello, world!");
  });

    const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
        console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
    });

    return server;
}