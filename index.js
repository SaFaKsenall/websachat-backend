import express from 'express';
import admin from 'firebase-admin';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import open from 'open';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import { createServer } from 'http';
import { Server } from 'socket.io';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

const app = express();
const server = createServer(app);
const io = new Server(server);
dotenv.config();

// View engine ayarları
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('trust proxy', true);

// Session ayarları
app.use(session({
  secret: process.env.SESSION_SECRET || 'gizli-anahtar',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 saat
  }
}));

// Auth Middleware
const requireLogin = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
};

// Firebase yapılandırması
try {
  let serviceAccount;
  if (process.env.FIREBASE_ADMIN_CREDENTIALS) {
    serviceAccount = JSON.parse(process.env.FIREBASE_ADMIN_CREDENTIALS);
  } else {
    serviceAccount = require('./jobapp-14c52-firebase-adminsdk-fujz3-f235da0fdd.json');
  }
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
    projectId: process.env.FIREBASE_PROJECT_ID
  });

  const db = admin.firestore();
  
  // Veritabanı bağlantısını test et
  db.collection('test').doc('test').get()
    .then(() => {
      console.log('✅ Firebase veritabanına başarıyla bağlanıldı!');
      console.log(`📁 Proje ID: ${process.env.FIREBASE_PROJECT_ID}`);
    })
    .catch((error) => {
      console.error('❌ Firebase veritabanına bağlanılamadı:', error);
      process.exit(1);
    });

} catch (error) {
  console.error('❌ Firebase başlatılamadı:', error);
  process.exit(1);
}

const db = admin.firestore();
const usersCollection = db.collection('users');
const roomsCollection = db.collection('rooms');

// Ana sayfa - Giriş yapılmamışsa login'e yönlendir
app.get('/', requireLogin, async (req, res) => {
  try {
    const userDoc = await usersCollection.doc(req.session.userId).get();
    const userData = userDoc.data();
    res.render('home', { 
      currentUser: {
        id: userDoc.id,
        ...userData
      }
    });
  } catch (error) {
    res.status(500).send('Bir hata oluştu: ' + error.message);
  }
});

// /home rotası için yönlendirme
app.get('/home', (req, res) => {
  res.redirect('/');
});

// Kayıt sayfası
app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.render('register');
});

// Login sayfası
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  res.render('login');
});

// Arama sayfası
app.get('/search', requireLogin, async (req, res) => {
  const { q } = req.query;
  try {
    let users = [];
    
    // AJAX isteği için HTML parçası döndür
    const renderSearchResults = () => {
      if (q && users.length > 0) {
        return `
          <h6 class="mb-3">
            "${q}" için arama sonuçları
            <small class="text-muted">(${users.length} kullanıcı)</small>
          </h6>
          <div class="search-results">
            <div class="row row-cols-1 row-cols-md-2 g-4">
              ${users.map(user => `
                <div class="col">
                  <div class="card h-100 user-card">
                    <div class="card-body">
                      <div class="d-flex justify-content-between align-items-center">
                        <div>
                          <h6 class="card-title mb-1">
                            ${user.username}
                            ${user.relevance === 'exact' ? '<span class="badge bg-primary">Tam Eşleşme</span>' : ''}
                          </h6>
                          <small class="text-muted">
                            ${user.followerCount || 0} takipçi • 
                            ${user.followingCount || 0} takip edilen
                          </small>
                        </div>
                        <a href="/profile/${user.id}" class="btn btn-outline-primary btn-sm">Profile Git</a>
                      </div>
                    </div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      } else {
        return `
          <div class="alert alert-info">
            ${q ? 'Kullanıcı bulunamadı. Farklı bir arama terimi deneyin.' : 'Kullanıcı aramak için yukarıdaki arama kutusunu kullanın.'}
          </div>
        `;
      }
    };

    // Sadece arama terimi varsa kullanıcıları getir
    if (q) {
      const snapshot = await usersCollection.get();
      const searchTerm = q.toLowerCase();
      const results = [];

      snapshot.forEach(doc => {
        const userData = doc.data();
        if (doc.id !== req.session.userId && 
            userData && 
            userData.username && 
            typeof userData.username === 'string') {
          
          const username = userData.username.toLowerCase();
          let relevance = null;

          // Tam eşleşme kontrolü
          if (username === searchTerm) {
            relevance = 'exact';
          }
          // Başlangıç eşleşmesi kontrolü
          else if (username.startsWith(searchTerm)) {
            relevance = 'starts';
          }
          // Kelime başlangıcı eşleşmesi kontrolü
          else if (username.includes(` ${searchTerm}`)) {
            relevance = 'word';
          }
          // İçerik eşleşmesi kontrolü
          else if (username.includes(searchTerm)) {
            relevance = 'contains';
          }

          if (relevance) {
            results.push({
              id: doc.id,
              username: userData.username,
              followerCount: userData.followerCount || 0,
              followingCount: userData.followingCount || 0,
              relevance
            });
          }
        }
      });

      // Sonuçları alaka düzeyine ve takipçi sayısına göre sırala
      users = results.sort((a, b) => {
        // Önce alaka düzeyine göre sırala
        const relevanceOrder = { exact: 0, starts: 1, word: 2, contains: 3 };
        const relevanceDiff = relevanceOrder[a.relevance] - relevanceOrder[b.relevance];
        
        if (relevanceDiff !== 0) return relevanceDiff;
        
        // Alaka düzeyi aynıysa takipçi sayısına göre sırala
        return b.followerCount - a.followerCount;
      });
    }

    // AJAX isteği mi kontrol et
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      res.send(`<div id="searchResults">${renderSearchResults()}</div>`);
    } else {
      res.render('search', { 
        users, 
        searchQuery: q,
        currentUserId: req.session.userId
      });
    }
  } catch (error) {
    res.status(500).send('Bir hata oluştu: ' + error.message);
  }
});

// Profil sayfası
app.get('/profile/:userId', requireLogin, async (req, res) => {
  try {
    const [userDoc, currentUserDoc] = await Promise.all([
      usersCollection.doc(req.params.userId).get(),
      usersCollection.doc(req.session.userId).get()
    ]);

    if (!userDoc.exists) {
      return res.status(404).send('Kullanıcı bulunamadı');
    }

    const userData = userDoc.data();
    const currentUserData = currentUserDoc.data();
    const isOwnProfile = req.session.userId === req.params.userId;
    const isFollowing = userData.followers.includes(req.session.userId);

    res.render('profile', {
      profile: {
        id: userDoc.id,
        ...userData
      },
      isOwnProfile,
      isFollowing,
      currentUserId: req.session.userId,
      currentUserCoins: currentUserData.coins || 0
    });
  } catch (error) {
    res.status(500).send('Bir hata oluştu: ' + error.message);
  }
});

// Kullanıcı oluşturma endpoint'i
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password || username.trim() === '' || password.trim() === '') {
      return res.status(400).json({ error: 'Kullanıcı adı ve şifre gereklidir' });
    }

    // Kullanıcı adının benzersiz olduğunu kontrol et
    const userSnapshot = await usersCollection.where('username', '==', username).get();
    if (!userSnapshot.empty) {
      return res.status(400).json({ error: 'Bu kullanıcı adı zaten kullanımda' });
    }

    const userDoc = await usersCollection.add({
      username: username.trim(),
      password: password.trim(), // Gerçek uygulamada şifreyi hashleyin!
      followers: [],
      following: [],
      followerCount: 0,
      followingCount: 0,
      coins: 100, // Yeni kullanıcıya 100 jeton ver
      gifts: {
        heart: 0,
        star: 0,
        diamond: 0,
        trophy: 0
      },
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.redirect('/login');
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login endpoint'i
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const userSnapshot = await usersCollection.where('username', '==', username).get();
    if (userSnapshot.empty) {
      return res.status(400).json({ error: 'Kullanıcı bulunamadı' });
    }

    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();

    if (userData.password !== password) { // Gerçek uygulamada hash karşılaştırması yapın!
      return res.status(400).json({ error: 'Hatalı şifre' });
    }

    req.session.userId = userDoc.id;
    res.redirect('/');
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Çıkış endpoint'i
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Kullanıcıyı takip etme endpoint'i
app.post('/api/users/:userId/follow', requireLogin, async (req, res) => {
  try {
    const { userId } = req.params;
    const followerId = req.session.userId;

    const userRef = usersCollection.doc(userId);
    const followerRef = usersCollection.doc(followerId);

    await db.runTransaction(async (transaction) => {
      const [userDoc, followerDoc] = await Promise.all([
        transaction.get(userRef),
        transaction.get(followerRef)
      ]);

      if (!userDoc.exists || !followerDoc.exists) {
        throw new Error('Kullanıcı bulunamadı');
      }

      const userData = userDoc.data();
      const followerData = followerDoc.data();

      if (!userData.followers.includes(followerId)) {
        transaction.update(userRef, {
          followers: admin.firestore.FieldValue.arrayUnion(followerId),
          followerCount: (userData.followerCount || 0) + 1
        });
        
        transaction.update(followerRef, {
          following: admin.firestore.FieldValue.arrayUnion(userId),
          followingCount: (followerData.followingCount || 0) + 1
        });
      }
    });

    res.redirect('/profile/' + userId);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Takibi bırakma endpoint'i
app.post('/api/users/:userId/unfollow', requireLogin, async (req, res) => {
  try {
    const { userId } = req.params;
    const followerId = req.session.userId;

    const userRef = usersCollection.doc(userId);
    const followerRef = usersCollection.doc(followerId);

    await db.runTransaction(async (transaction) => {
      const [userDoc, followerDoc] = await Promise.all([
        transaction.get(userRef),
        transaction.get(followerRef)
      ]);

      if (!userDoc.exists || !followerDoc.exists) {
        throw new Error('Kullanıcı bulunamadı');
      }

      const userData = userDoc.data();
      const followerData = followerDoc.data();

      transaction.update(userRef, {
        followers: admin.firestore.FieldValue.arrayRemove(followerId),
        followerCount: Math.max(0, (userData.followerCount || 1) - 1)
      });
      
      transaction.update(followerRef, {
        following: admin.firestore.FieldValue.arrayRemove(userId),
        followingCount: Math.max(0, (followerData.followingCount || 1) - 1)
      });
    });

    res.redirect('/profile/' + userId);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Konum sayfası
app.get('/location', requireLogin, (req, res) => {
  res.render('location', {
    currentUserId: req.session.userId
  });
});

// Oda sayfası
app.get('/room/:roomId', requireLogin, async (req, res) => {
  try {
    const userDoc = await usersCollection.doc(req.session.userId).get();
    const userData = userDoc.data();
    
    // Oda bilgilerini kontrol et
    const roomDoc = await roomsCollection.doc(req.params.roomId).get();
    if (!roomDoc.exists) {
      return res.status(404).send('Oda bulunamadı');
    }
    
    const roomData = roomDoc.data();
    
    // Şifreli oda kontrolü
    if (roomData.password && !req.session.authorizedRooms?.includes(req.params.roomId)) {
      return res.render('room-auth', {
        roomId: req.params.roomId,
        roomName: roomData.name || `Oda ${req.params.roomId}`
      });
    }
    
    // Kullanıcı sayısı kontrolü
    if (roomData.connectedUsers?.length >= roomData.maxUsers) {
      return res.status(403).send('Oda maksimum kapasiteye ulaştı');
    }

    res.render('room', {
      roomId: req.params.roomId,
      roomName: roomData.name || `Oda ${req.params.roomId}`,
      currentUserId: req.session.userId,
      username: userData.username,
      isOwner: roomData.ownerId === req.session.userId
    });
  } catch (error) {
    res.status(500).send('Bir hata oluştu: ' + error.message);
  }
});

// Oda şifre kontrolü
app.post('/api/rooms/:roomId/auth', requireLogin, async (req, res) => {
  try {
    const { password } = req.body;
    const roomDoc = await roomsCollection.doc(req.params.roomId).get();
    
    if (!roomDoc.exists) {
      return res.status(404).json({ error: 'Oda bulunamadı' });
    }
    
    const roomData = roomDoc.data();
    
    if (roomData.password !== password) {
      return res.status(403).json({ error: 'Yanlış şifre' });
    }
    
    // Oturuma yetkili odayı ekle
    if (!req.session.authorizedRooms) {
      req.session.authorizedRooms = [];
    }
    req.session.authorizedRooms.push(req.params.roomId);
    
    res.redirect(`/room/${req.params.roomId}`);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Kullanıcı mikrofon kontrolü
app.post('/api/rooms/:roomId/mute/:userId', requireLogin, async (req, res) => {
  try {
    const roomDoc = await roomsCollection.doc(req.params.roomId).get();
    if (!roomDoc.exists) {
      return res.status(404).json({ error: 'Oda bulunamadı' });
    }
    
    const roomData = roomDoc.data();
    if (roomData.ownerId !== req.session.userId) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    const { action } = req.body; // 'mute' veya 'unmute'
    
    // Kullanıcının mute durumunu güncelle
    await roomsCollection.doc(req.params.roomId).update({
      mutedUsers: action === 'mute' 
        ? admin.firestore.FieldValue.arrayUnion(req.params.userId)
        : admin.firestore.FieldValue.arrayRemove(req.params.userId)
    });
    
    // Socket.IO üzerinden kullanıcıya mikrofon sinyali gönder
    io.to(req.params.roomId).emit(action === 'mute' ? 'mute-user' : 'unmute-user', req.params.userId);
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Oda ayarlarını güncelle
app.post('/api/rooms/:roomId/settings', requireLogin, async (req, res) => {
  try {
    const { maxUsers, isPasswordProtected, password } = req.body;
    const roomDoc = await roomsCollection.doc(req.params.roomId).get();
    
    if (!roomDoc.exists) {
      return res.status(404).json({ error: 'Oda bulunamadı' });
    }
    
    const roomData = roomDoc.data();
    if (roomData.ownerId !== req.session.userId) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }

    // Kullanıcı sayısı kontrolü
    const userLimit = parseInt(maxUsers);
    if (isNaN(userLimit) || userLimit < 1 || userLimit > 8) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı sayısı' });
    }

    // Şifre kontrolü
    if (isPasswordProtected && !password) {
      return res.status(400).json({ error: 'Şifreli oda için şifre gereklidir' });
    }

    // Mevcut bağlı kullanıcı sayısı kontrolü
    if (roomData.connectedUsers?.length > userLimit) {
      return res.status(400).json({ error: 'Yeni kullanıcı limiti mevcut bağlı kullanıcı sayısından küçük olamaz' });
    }
    
    await roomsCollection.doc(req.params.roomId).update({
      maxUsers: userLimit,
      password: isPasswordProtected ? password : null
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Oda oluşturma endpoint'i
app.post('/api/rooms', requireLogin, async (req, res) => {
  try {
    const { roomName, isPasswordProtected, password, maxUsers } = req.body;
    
    if (!roomName) {
      return res.status(400).json({ error: 'Oda adı gereklidir' });
    }

    // Şifre kontrolü
    if (isPasswordProtected === 'true' && !password) {
      return res.status(400).json({ error: 'Şifreli oda için şifre gereklidir' });
    }

    // Kullanıcı sayısı kontrolü
    const userLimit = parseInt(maxUsers);
    if (isNaN(userLimit) || userLimit < 1 || userLimit > 8) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı sayısı' });
    }

    const roomDoc = await roomsCollection.add({
      name: roomName,
      password: isPasswordProtected === 'true' ? password : null,
      maxUsers: userLimit,
      ownerId: req.session.userId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      connectedUsers: [],
      mutedUsers: [] // Susturulan kullanıcılar listesi
    });

    res.redirect(`/room/${roomDoc.id}`);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Hediye gönderme endpoint'i
app.post('/api/users/:userId/send-gift', requireLogin, async (req, res) => {
  try {
    const { giftType } = req.body;
    const senderId = req.session.userId;
    const receiverId = req.params.userId;

    // Hediye fiyatları
    const giftPrices = {
      heart: 10,
      star: 25,
      diamond: 50,
      trophy: 100
    };

    if (!giftPrices[giftType]) {
      return res.status(400).json({ error: 'Geçersiz hediye türü' });
    }

    const price = giftPrices[giftType];

    await db.runTransaction(async (transaction) => {
      // Gönderen ve alıcı kullanıcıları al
      const senderRef = usersCollection.doc(senderId);
      const receiverRef = usersCollection.doc(receiverId);
      
      const [senderDoc, receiverDoc] = await Promise.all([
        transaction.get(senderRef),
        transaction.get(receiverRef)
      ]);

      if (!senderDoc.exists || !receiverDoc.exists) {
        throw new Error('Kullanıcı bulunamadı');
      }

      const senderData = senderDoc.data();
      const receiverData = receiverDoc.data();

      // Yeterli jeton kontrolü
      if ((senderData.coins || 0) < price) {
        throw new Error('Yetersiz jeton');
      }

      // Jetonları ve hediyeleri güncelle
      transaction.update(senderRef, {
        coins: admin.firestore.FieldValue.increment(-price)
      });

      transaction.update(receiverRef, {
        [`gifts.${giftType}`]: admin.firestore.FieldValue.increment(1)
      });
    });

    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Jeton satın alma endpoint'i (gerçek uygulamada ödeme sistemi entegre edilmeli)
app.post('/api/users/buy-coins', requireLogin, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.session.userId;

    // Jeton miktarını güncelle
    await usersCollection.doc(userId).update({
      coins: admin.firestore.FieldValue.increment(parseInt(amount))
    });

    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Socket.IO olayları
io.on('connection', (socket) => {
  console.log('Yeni bağlantı:', socket.id);

  socket.on('join-room', async ({ roomId, userId, username }) => {
    try {
      const roomDoc = await roomsCollection.doc(roomId).get();
      if (!roomDoc.exists) {
        socket.emit('error', 'Oda bulunamadı');
        return;
      }
      
      const roomData = roomDoc.data();
      
      // Kullanıcı sayısı kontrolü
      if (roomData.connectedUsers?.length >= roomData.maxUsers) {
        socket.emit('error', 'Oda maksimum kapasiteye ulaştı');
        return;
      }
      
      // Kullanıcıyı odaya ekle
      await roomsCollection.doc(roomId).update({
        connectedUsers: admin.firestore.FieldValue.arrayUnion({
          userId,
          username,
          socketId: socket.id
        })
      });

      console.log(`${username} (${userId}) odaya katıldı: ${roomId}`);
      socket.join(roomId);
      socket.userId = userId;
      socket.username = username;
      socket.roomId = roomId;
      
      // Odadaki diğer kullanıcılara bildir
      socket.to(roomId).emit('user-connected', userId, username);

      // Odadaki mevcut kullanıcıları gönder
      const updatedRoomDoc = await roomsCollection.doc(roomId).get();
      const updatedRoomData = updatedRoomDoc.data();
      socket.emit('room-users', updatedRoomData.connectedUsers || []);
      socket.to(roomId).emit('room-users', updatedRoomData.connectedUsers || []);
    } catch (error) {
      console.error('Odaya katılma hatası:', error);
      socket.emit('error', 'Odaya katılırken bir hata oluştu');
    }
  });

  socket.on('request-users', async (roomId) => {
    try {
      const roomDoc = await roomsCollection.doc(roomId).get();
      if (roomDoc.exists) {
        const roomData = roomDoc.data();
        io.to(roomId).emit('room-users', roomData.connectedUsers || []);
      }
    } catch (error) {
      console.error('Kullanıcı listesi alma hatası:', error);
    }
  });

  socket.on('signal', ({ userId, signal }) => {
    console.log(`Sinyal gönderildi: ${socket.username} -> ${userId}`);
    socket.to(socket.roomId).emit('signal', {
      userId: socket.userId,
      signal
    });
  });

  socket.on('disconnect', async () => {
    console.log(`Bağlantı kesildi: ${socket.username}`);
    if (socket.roomId) {
      try {
        const roomDoc = await roomsCollection.doc(socket.roomId).get();
        if (roomDoc.exists) {
          const roomData = roomDoc.data();
          const updatedUsers = (roomData.connectedUsers || []).filter(
            user => user.socketId !== socket.id
          );
          
          await roomsCollection.doc(socket.roomId).update({
            connectedUsers: updatedUsers
          });
          
          socket.to(socket.roomId).emit('user-disconnected', socket.userId);
          socket.to(socket.roomId).emit('room-users', updatedUsers);
        }
      } catch (error) {
        console.error('Kullanıcı çıkarma hatası:', error);
      }
    }
  });
});

let port = process.env.PORT || 5000;

const startServer = (port) => {
  server.listen(port, () => {
    console.log('🚀 Sunucu başlatılıyor...');
    console.log(`✅ Sunucu http://localhost:${port} adresinde çalışıyor`);
    
    // Tarayıcıyı aç
    open(`http://localhost:${port}`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`⚠️ Port ${port} kullanımda. Başka bir port deneniyor...`);
      startServer(port + 1);
    } else {
      console.error('❌ Sunucu hatası:', err);
      process.exit(1);
    }
  });
};

// Sunucuyu başlat
console.log('🔄 Sistem başlatılıyor...');
startServer(port);
