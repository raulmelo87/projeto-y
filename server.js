const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();

// Configuração do express-session para gerenciar sessões de usuário
app.use(session({
    secret: 'seuSegredoAqui',
    resave: false,
    saveUninitialized: false
}));

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(express.urlencoded({ extended: true }));

// Conexão com o MongoDB Atlas
const mongoURI = 'mongodb+srv://fraulbmelo:Chess0010@cluster0.sximque.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Conectado ao MongoDB Atlas'))
.then(() => console.log('Acesse "localhost:3000" em seu navegador'))
.catch(err => console.log('Erro na conexão com o MongoDB:', err));

// MODELOS - USUÁRIOS E DENÚNCIA

// Modelo de Usuário
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    isAdmin: { type: Boolean, default: false }  // campo para identificar administradores
});
const User = mongoose.model('User', userSchema);

// Modelo de Denúncia (agora vinculada ao usuário que a criou)
// Campo "aprovado" determina se a denúncia foi avaliada e liberada para exibição
const denunciaSchema = new mongoose.Schema({
    descricao: String,
    imagem: String,
    resolvido: { type: Boolean, default: false },
    data: { type: Date, default: Date.now },
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    aprovado: { type: Boolean, default: false } // denuncia fica pendente de aprovação
});
const Denuncia = mongoose.model('Denuncia', denunciaSchema);

// CONFIGURAÇÃO DO MULTER (UPLOAD)

const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function(req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// MIDDLEWARE PARA VERIFICAÇÃO DE LOGIN

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

// MIDDLEWARE PARA VERIFICAÇÃO DE ADMINISTRADOR

function isAdmin(req, res, next) {
    // Se o usuário estiver logado e tiver isAdmin definido na sessão, permite acesso
    if (req.session.userId && req.session.isAdmin) {
        return next();
    } else {
        return res.status(403).send('Acesso negado: apenas administradores podem acessar essa rota');
    }
}

// ROTAS - AUTENTICAÇÃO   

// Página de registro (GET)
app.get('/register', (req, res) => {
    res.render('register');
});

// Registro de usuário (POST)
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // Criptografa a senha antes de salvar
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.redirect('/login');
    } catch (err) {
        res.status(500).send('Erro no registro: ' + err);
    }
});

// Página de login (GET)
app.get('/login', (req, res) => {
    res.render('login');
});

// Login (POST)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.redirect('/login?error=' + encodeURIComponent('Usuário não encontrado'));
        }
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.userId = user._id;
            req.session.username = user.username; // Armazena o nome do usuário na sessão
            req.session.isAdmin = user.isAdmin;
            res.redirect('/');
        } else {
            return res.redirect('/login?error=' + encodeURIComponent('Senha incorreta'));
        }
    } catch (err) {
        res.status(500).send('Erro no login: ' + err);
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// ROTAS - DENÚNCIAS   

// Página principal: exibe apenas as denúncias aprovadas, com filtro opcional
app.get('/', async (req, res) => {
    try {
        let query = { aprovado: true };

        if (req.query.q) {
            query.descricao = { $regex: req.query.q, $options: 'i' };
        }

        const denuncias = await Denuncia.find(query).sort({ data: -1 }).populate('usuario');
        const message = req.session.message || null;
        req.session.message = null;

        res.render('index', { 
            denuncias, 
            userId: req.session.userId, 
            username: req.session.username, // Passa o nome do usuário para a view
            isAdmin: req.session.isAdmin || false,
            message,
            search: req.query.q || ''
        });
    } catch (err) {
        res.status(500).send('Erro ao buscar denúncias');
    }
});

// Configuração do Nodemailer para conta Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'raul.kmkz87@gmail.com', // Conta que transmite o e-mail
        pass: 'nbrzbhxpozrcaqrc' // Senha de aplicativo (sem espaços)
    }
});


// Rota para submeter uma nova denúncia (somente usuários logados podem enviar)
// A denúncia é salva com "aprovado: false", aguardando avaliação do administrador
app.post('/denunciar', isAuthenticated, upload.single('imagem'), async (req, res) => {
    try {
        // Verifica se a descrição e a imagem foram enviadas, e se o arquivo possui conteúdo
        if (!req.body.descricao || !req.file || req.file.size === 0) {
            return res.status(400).send('Erro: Denúncia deve conter texto e imagem');
        }

        const novaDenuncia = new Denuncia({
            descricao: req.body.descricao,
            imagem: req.file.filename,
            usuario: req.session.userId,
            aprovado: false
        });

        await novaDenuncia.save();

        // Envio do e-mail de notificação para o administrador
        const mailOptions = {
            from: 'raul.kmkz87@gmail.com', // Conta remetente
            to: 'fraulbmelo@gmail.com',   // Conta do administrador
            subject: 'Nova Denúncia Recebida',
            text: `Uma nova denúncia foi publicada.\n\nDescrição: ${req.body.descricao}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Erro ao enviar e-mail:', error);
            } else {
                console.log('E-mail enviado:', info.response);
            }
        });

        // Define uma mensagem de sucesso na sessão para informar o usuário
        req.session.message = 'Sua denúncia foi enviada para avaliação do administrador e em breve poderá ser publicada.';
        res.redirect('/');
        
    } catch (err) {
        console.error('Erro ao salvar a denúncia:', err);
        res.status(500).send('Erro ao salvar a denúncia');
    }
});

// Rota para atualizar o status da denúncia (somente o autor pode alterar o status)
app.post('/denuncia/:id/status', isAuthenticated, async (req, res) => {
    try {
        const denuncia = await Denuncia.findById(req.params.id);
        if (!denuncia) {
            return res.status(404).send('Denúncia não encontrada');
        }
        // Verifica se o usuário logado é o criador da denúncia
        if (denuncia.usuario.toString() !== req.session.userId.toString()) {
            return res.status(403).send('Você não tem permissão para alterar esta denúncia');
        }
        const { status } = req.body; // "true" ou "false" (em formato string)
        denuncia.resolvido = status === 'true';
        await denuncia.save();
        res.redirect('/');
    } catch (err) {
        res.status(500).send('Erro ao atualizar status');
    }
});

// ROTAS - ADMINISTRAÇÃO   

// Rota para exibir denúncias pendentes (apenas para administradores)
app.get('/admin', isAdmin, async (req, res) => {
    try {
        const pendingDenuncias = await Denuncia.find({ aprovado: false }).populate('usuario');
        res.render('admin', { pendingDenuncias });
    } catch (err) {
        res.status(500).send('Erro ao buscar denúncias pendentes');
    }
});

// Rota para aprovar uma denúncia (apenas para administradores)
app.post('/denuncia/:id/aprovar', isAdmin, async (req, res) => {
    try {
        const denuncia = await Denuncia.findById(req.params.id);
        if (!denuncia) {
            return res.status(404).send('Denúncia não encontrada');
        }
        denuncia.aprovado = true;
        await denuncia.save();
        res.redirect('/admin');
    } catch (err) {
        res.status(500).send('Erro ao aprovar a denúncia');
    }
});

// Rota para deletar uma denúncia (apenas para administradores)
app.post('/denuncia/:id/delete', isAdmin, async (req, res) => {
    try {
      await Denuncia.findByIdAndDelete(req.params.id);
      res.redirect('/admin');
    } catch (err) {
      res.status(500).send('Erro ao deletar a denúncia');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
