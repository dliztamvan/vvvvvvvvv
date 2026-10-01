const HEADERS = {
  "content-type": "application/json; charset=UTF-8",
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type,authorization",
  "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: HEADERS
  });
}

const now = () => Date.now();
const makeId = () => crypto.randomUUID();
const encoder = new TextEncoder();

async function sha256(text) {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(text)
  );

  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function readBody(request) {
  try {
    const contentType =
      request.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      return {};
    }

    return await request.json();
  } catch {
    return {};
  }
}

function fee(price) {
  const p = Number(price);

  if (!Number.isFinite(p) || p < 0) {
    return 0;
  }

  if (p < 100000) return 1000;
  if (p < 1000000) return 2500;

  return 5000;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    verified: Boolean(user.verified),
    balance: Number(user.balance || 0)
  };
}

async function getUser(request, env) {
  const authorization =
    request.headers.get("authorization") || "";

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  const token = authorization.slice(7).trim();

  if (!token) {
    return null;
  }

  return await env.DB.prepare(`
    SELECT u.*
    FROM sessions s
    INNER JOIN users u
      ON u.id = s.user_id
    WHERE s.token = ?
      AND s.expires_at > ?
    LIMIT 1
  `)
    .bind(token, now())
    .first();
}

function isAdmin(user) {
  return user && user.role === "admin";
}

async function encryptDelivery(text, secret) {
  if (!secret) {
    throw new Error("DELIVERY_SECRET belum diset");
  }

  const hash = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(secret)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    hash,
    {
      name: "AES-GCM"
    },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(
    new Uint8Array(12)
  );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      encoder.encode(text)
    );

  const result = new Uint8Array(
    iv.length + encrypted.byteLength
  );

  result.set(iv, 0);
  result.set(
    new Uint8Array(encrypted),
    iv.length
  );

  return btoa(
    String.fromCharCode(...result)
  );
}

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // =========================
  // CORS
  // =========================

  if (method === "OPTIONS") {
    return json({
      ok: true
    });
  }

  // =========================
  // HEALTH
  // =========================

  if (
    path === "/api/health" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      service: "Velora Backend",
      version: "10.1",
      database: "Cloudflare D1",
      time: now()
    });
  }

  // =========================
  // REGISTER
  // =========================

  if (
    path === "/api/auth/register" &&
    method === "POST"
  ) {
    const body = await readBody(request);

    const name =
      String(body.name || "").trim();

    const email =
      String(body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(body.password || "");

    if (!name || !email || !password) {
      return json({
        error:
          "Nama, email dan password wajib diisi"
      }, 400);
    }

    if (name.length < 2) {
      return json({
        error:
          "Nama minimal 2 karakter"
      }, 400);
    }

    if (
      !/^[^@\s]+@gmail\.com$/i.test(email)
    ) {
      return json({
        error:
          "Gunakan alamat Gmail"
      }, 400);
    }

    if (password.length < 6) {
      return json({
        error:
          "Password minimal 6 karakter"
      }, 400);
    }

    const exists =
      await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
        .bind(email)
        .first();

    if (exists) {
      return json({
        error:
          "Email sudah terdaftar"
      }, 409);
    }

    const userId = makeId();

    const passwordHash =
      await sha256(
        userId + ":" + password
      );

    await env.DB.prepare(`
      INSERT INTO users
      (
        id,
        email,
        name,
        password_hash,
        role,
        verified,
        balance,
        created_at
      )
      VALUES
      (?, ?, ?, ?, 'user', 0, 0, ?)
    `)
      .bind(
        userId,
        email,
        name,
        passwordHash,
        now()
      )
      .run();

    return json({
      ok: true,
      message:
        "Akun berhasil dibuat"
    }, 201);
  }

  // =========================
  // LOGIN
  // =========================

  if (
    path === "/api/auth/login" &&
    method === "POST"
  ) {
    const body = await readBody(request);

    const email =
      String(body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(body.password || "");

    if (!email || !password) {
      return json({
        error:
          "Email dan password wajib diisi"
      }, 400);
    }

    const user =
      await env.DB.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
        LIMIT 1
      `)
        .bind(email)
        .first();

    if (!user) {
      return json({
        error:
          "Email atau password salah"
      }, 401);
    }

    const passwordHash =
      await sha256(
        user.id + ":" + password
      );

    if (
      passwordHash !==
      user.password_hash
    ) {
      return json({
        error:
          "Email atau password salah"
      }, 401);
    }

    const token =
      makeId() +
      makeId().replaceAll("-", "");

    const expires =
      now() +
      30 * 24 * 60 * 60 * 1000;

    await env.DB.prepare(`
      INSERT INTO sessions
      (
        token,
        user_id,
        expires_at
      )
      VALUES (?, ?, ?)
    `)
      .bind(
        token,
        user.id,
        expires
      )
      .run();

    return json({
      ok: true,
      token,
      expires_at: expires,
      user: publicUser(user)
    });
  }

  // =========================
  // AUTH CHECK
  // =========================

  const user =
    await getUser(
      request,
      env
    );

  if (!user) {
    return json({
      error:
        "Unauthorized"
    }, 401);
  }

  // =========================
  // ME
  // =========================

  if (
    path === "/api/me" &&
    method === "GET"
  ) {
    return json({
      ok: true,
      user: publicUser(user)
    });
  }

  // =========================
  // PRODUCTS GET
  // =========================

  if (
    path === "/api/products" &&
    method === "GET"
  ) {
    const q =
      String(
        url.searchParams.get("q") || ""
      )
        .trim()
        .toLowerCase();

    let sql = `
      SELECT
        p.*,
        u.name AS seller_name,
        u.verified AS seller_verified
      FROM products p
      INNER JOIN users u
        ON u.id = p.seller_id
      WHERE p.active = 1
    `;

    const args = [];

    if (q) {
      sql += `
        AND lower(
          COALESCE(p.title, '') || ' ' ||
          COALESCE(p.game, '') || ' ' ||
          COALESCE(p.description, '') || ' ' ||
          COALESCE(u.name, '')
        ) LIKE ?
      `;

      args.push(`%${q}%`);
    }

    sql += `
      ORDER BY p.created_at DESC
      LIMIT 100
    `;

    const result =
      await env.DB.prepare(sql)
        .bind(...args)
        .all();

    return json({
      ok: true,
      products:
        result.results || []
    });
  }

  // =========================
  // ADD PRODUCT
  // =========================

  if (
    path === "/api/products" &&
    method === "POST"
  ) {
    if (
      user.role !== "seller" &&
      user.role !== "admin"
    ) {
      return json({
        error:
          "Hanya seller yang dapat menjual"
      }, 403);
    }

    const body =
      await readBody(request);

    const title =
      String(body.title || "").trim();

    const game =
      String(body.game || "").trim();

    const description =
      String(
        body.description || ""
      ).trim();

    const price =
      Number(body.price);

    if (
      !title ||
      !game ||
      !Number.isFinite(price) ||
      price <= 0
    ) {
      return json({
        error:
          "Data produk tidak valid"
      }, 400);
    }

    const productId =
      makeId();

    await env.DB.prepare(`
      INSERT INTO products
      (
        id,
        seller_id,
        title,
        game,
        description,
        price,
        active,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, ?, 1, ?)
    `)
      .bind(
        productId,
        user.id,
        title,
        game,
        description,
        price,
        now()
      )
      .run();

    return json({
      ok: true,
      id: productId
    }, 201);
  }

  // =========================
  // CREATE TRANSACTION
  // =========================

  if (
    path === "/api/transactions" &&
    method === "POST"
  ) {
    const body =
      await readBody(request);

    const productId =
      String(
        body.productId || ""
      ).trim();

    if (!productId) {
      return json({
        error:
          "productId wajib diisi"
      }, 400);
    }

    const product =
      await env.DB.prepare(`
        SELECT *
        FROM products
        WHERE id = ?
          AND active = 1
        LIMIT 1
      `)
        .bind(productId)
        .first();

    if (!product) {
      return json({
        error:
          "Produk tidak ditemukan"
      }, 404);
    }

    if (
      product.seller_id ===
      user.id
    ) {
      return json({
        error:
          "Tidak dapat membeli produk sendiri"
      }, 400);
    }

    const productFee =
      fee(product.price);

    const total =
      Number(product.price) +
      productFee;

    const transactionId =
      makeId();

    await env.DB.prepare(`
      INSERT INTO transactions
      (
        id,
        buyer_id,
        seller_id,
        product_id,
        title,
        price,
        fee,
        total,
        status,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, 'waiting_payment', ?)
    `)
      .bind(
        transactionId,
        user.id,
        product.seller_id,
        product.id,
        product.title,
        product.price,
        productFee,
        total,
        now()
      )
      .run();

    await env.DB.prepare(`
      INSERT INTO messages
      (
        id,
        room_id,
        uid,
        name,
        role,
        text,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        makeId(),
        transactionId,
        user.id,
        user.name,
        user.role,
        "Transaksi dibuat. Buyer, seller dan admin dapat menggunakan ruang chat transaksi ini.",
        now()
      )
      .run();

    return json({
      ok: true,
      id: transactionId,
      price: Number(product.price),
      fee: productFee,
      total,
      status:
        "waiting_payment"
    }, 201);
  }

  // =========================
  // USER TRANSACTIONS
  // =========================

  if (
    path === "/api/transactions" &&
    method === "GET"
  ) {
    const result =
      await env.DB.prepare(`
        SELECT *
        FROM transactions
        WHERE buyer_id = ?
           OR seller_id = ?
        ORDER BY created_at DESC
      `)
        .bind(
          user.id,
          user.id
        )
        .all();

    return json({
      ok: true,
      transactions:
        result.results || []
    });
  }

  // =========================
  // ADMIN TRANSACTIONS
  // =========================

  if (
    path === "/api/admin/transactions" &&
    method === "GET"
  ) {
    if (!isAdmin(user)) {
      return json({
        error:
          "Admin only"
      }, 403);
    }

    const result =
      await env.DB.prepare(`
        SELECT *
        FROM transactions
        ORDER BY created_at DESC
        LIMIT 500
      `)
        .all();

    return json({
      ok: true,
      transactions:
        result.results || []
    });
  }

  // =========================
  // ADMIN UPDATE STATUS
  // =========================

  const adminStatus =
    path.match(
      /^\/api\/admin\/transactions\/([^/]+)\/status$/
    );

  if (
    adminStatus &&
    method === "PATCH"
  ) {
    if (!isAdmin(user)) {
      return json({
        error:
          "Admin only"
      }, 403);
    }

    const transactionId =
      adminStatus[1];

    const body =
      await readBody(request);

    const status =
      String(
        body.status || ""
      ).trim();

    const allowed = [
      "waiting_payment",
      "payment_verified",
      "delivered",
      "completed",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return json({
        error:
          "Status tidak valid"
      }, 400);
    }

    const transaction =
      await env.DB.prepare(`
        SELECT *
        FROM transactions
        WHERE id = ?
        LIMIT 1
      `)
        .bind(transactionId)
        .first();

    if (!transaction) {
      return json({
        error:
          "Transaksi tidak ditemukan"
      }, 404);
    }

    await env.DB.prepare(`
      UPDATE transactions
      SET status = ?
      WHERE id = ?
    `)
      .bind(
        status,
        transactionId
      )
      .run();

    await env.DB.prepare(`
      INSERT INTO messages
      (
        id,
        room_id,
        uid,
        name,
        role,
        text,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        makeId(),
        transactionId,
        user.id,
        user.name,
        "admin",
        "Status transaksi diubah menjadi: " + status,
        now()
      )
      .run();

    return json({
      ok: true,
      status
    });
  }

  // =========================
  // TRANSACTION MESSAGES
  // =========================

  const messageRoute =
    path.match(
      /^\/api\/transactions\/([^/]+)\/messages$/
    );

  if (
    messageRoute &&
    (method === "GET" ||
      method === "POST")
  ) {
    const transactionId =
      messageRoute[1];

    const transaction =
      await env.DB.prepare(`
        SELECT *
        FROM transactions
        WHERE id = ?
          AND (
            buyer_id = ?
            OR seller_id = ?
            OR ? = 'admin'
          )
        LIMIT 1
      `)
        .bind(
          transactionId,
          user.id,
          user.id,
          user.role
        )
        .first();

    if (!transaction) {
      return json({
        error:
          "Forbidden"
      }, 403);
    }

    if (method === "GET") {
      const result =
        await env.DB.prepare(`
          SELECT *
          FROM messages
          WHERE room_id = ?
          ORDER BY created_at ASC
        `)
          .bind(transactionId)
          .all();

      return json({
        ok: true,
        messages:
          result.results || []
      });
    }

    const body =
      await readBody(request);

    const text =
      String(
        body.text || ""
      ).trim();

    if (!text) {
      return json({
        error:
          "Pesan kosong"
      }, 400);
    }

    const messageId =
      makeId();

    await env.DB.prepare(`
      INSERT INTO messages
      (
        id,
        room_id,
        uid,
        name,
        role,
        text,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        messageId,
        transactionId,
        user.id,
        user.name,
        user.role,
        text,
        now()
      )
      .run();

    return json({
      ok: true,
      id: messageId
    }, 201);
  }

  // =========================
  // SELLER DELIVERY
  // =========================

  const deliveryRoute =
    path.match(
      /^\/api\/transactions\/([^/]+)\/delivery$/
    );

  if (
    deliveryRoute &&
    method === "POST"
  ) {
    if (
      user.role !== "seller" &&
      user.role !== "admin"
    ) {
      return json({
        error:
          "Seller only"
      }, 403);
    }

    const transactionId =
      deliveryRoute[1];

    const transaction =
      await env.DB.prepare(`
        SELECT *
        FROM transactions
        WHERE id = ?
          AND seller_id = ?
        LIMIT 1
      `)
        .bind(
          transactionId,
          user.id
        )
        .first();

    if (!transaction) {
      return json({
        error:
          "Seller tidak memiliki transaksi ini"
      }, 403);
    }

    if (
      transaction.status !==
      "payment_verified"
    ) {
      return json({
        error:
          "Pembayaran belum diverifikasi admin"
      }, 400);
    }

    const body =
      await readBody(request);

    const email =
      String(
        body.email || ""
      )
        .trim()
        .toLowerCase();

    const password =
      String(
        body.password || ""
      );

    if (
      !/^[^@\s]+@gmail\.com$/i.test(email)
    ) {
      return json({
        error:
          "Email akun wajib Gmail"
      }, 400);
    }

    if (!password) {
      return json({
        error:
          "Password akun wajib diisi"
      }, 400);
    }

    const cipher =
      await encryptDelivery(
        JSON.stringify({
          email,
          password
        }),
        env.DELIVERY_SECRET
      );

    await env.DB.prepare(`
      INSERT OR REPLACE INTO deliveries
      (
        transaction_id,
        email,
        password_cipher,
        created_at
      )
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        transactionId,
        email,
        cipher,
        now()
      )
      .run();

    await env.DB.prepare(`
      UPDATE transactions
      SET status = 'delivered'
      WHERE id = ?
    `)
      .bind(transactionId)
      .run();

    return json({
      ok: true,
      status:
        "delivered"
    });
  }

  // =========================
  // WITHDRAWAL
  // =========================

  if (
    path === "/api/withdrawals" &&
    method === "POST"
  ) {
    if (user.role !== "seller") {
      return json({
        error:
          "Seller only"
      }, 403);
    }

    const body =
      await readBody(request);

    const amount =
      Number(body.amount);

    const methodName =
      String(
        body.method || ""
      ).trim();

    const destination =
      String(
        body.destination || ""
      ).trim();

    if (
      !Number.isFinite(amount) ||
      amount < 10000 ||
      amount > Number(user.balance)
    ) {
      return json({
        error:
          "Nominal withdrawal tidak valid"
      }, 400);
    }

    if (
      !methodName ||
      !destination
    ) {
      return json({
        error:
          "Metode dan tujuan wajib diisi"
      }, 400);
    }

    const withdrawalId =
      makeId();

    await env.DB.prepare(`
      INSERT INTO withdrawals
      (
        id,
        seller_id,
        amount,
        method,
        destination,
        status,
        created_at
      )
      VALUES
      (?, ?, ?, ?, ?, 'requested', ?)
    `)
      .bind(
        withdrawalId,
        user.id,
        amount,
        methodName,
        destination,
        now()
      )
      .run();

    return json({
      ok: true,
      id: withdrawalId,
      status:
        "requested"
    }, 201);
  }

  // =========================
  // ADMIN USERS
  // =========================

  if (
    path === "/api/admin/users" &&
    method === "GET"
  ) {
    if (!isAdmin(user)) {
      return json({
        error:
          "Admin only"
      }, 403);
    }

    const result =
      await env.DB.prepare(`
        SELECT
          id,
          email,
          name,
          role,
          verified,
          balance,
          created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 500
      `)
        .all();

    return json({
      ok: true,
      users:
        result.results || []
    });
  }

  // =========================
  // NOT FOUND
  // =========================

  return json({
    error:
      "Endpoint tidak ditemukan",
    path,
    method
  }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await route(
        request,
        env
      );
    } catch (error) {
      console.error(error);

      return json({
        error:
          "Server error",
        detail:
          String(error)
      }, 500);
    }
  }
};
