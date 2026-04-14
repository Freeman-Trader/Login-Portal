require('dotenv').config();
const os = require('os');
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');
const winston = require('winston');

const app = express();

// -------------------------
// Host Info Configuration
// -------------------------
const hostname = os.hostname();
const getHostIp = () => {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                return net.address;
            }
        }
    }
    return '127.0.0.1';
};
const host_ip = getHostIp();

// -------------------------
// Custom Apache Log Formatters
// -------------------------
const getUtcAccessTimestamp = () => {
    const d = new Date();
    const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const day = String(d.getUTCDate()).padStart(2, '0');
    const month = months[d.getUTCMonth()];
    const year = d.getUTCFullYear();
    const time = `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}:${String(d.getUTCSeconds()).padStart(2, '0')}`;
    return `${day}/${month}/${year}:${time} +0000`;
};

const getUtcErrorTimestamp = () => {
    const d = new Date();
    const days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const dayName = days[d.getUTCDay()];
    const month = months[d.getUTCMonth()];
    const date = String(d.getUTCDate()).padStart(2, '0');
    const time = `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}:${String(d.getUTCSeconds()).padStart(2, '0')}`;
    const year = d.getUTCFullYear();
    return `${dayName} ${month} ${date} ${time} ${year}`;
};

// -------------------------
// Logging Setup (Winston)
// -------------------------
const accessLogger = winston.createLogger({
    level: 'info',
    format: winston.format.printf(info => info.message),
    transports: [
        new winston.transports.File({ filename: 'access.log', maxsize: 1000000, maxFiles: 5 })
    ]
});

const errorLogger = winston.createLogger({
    level: 'error',
    format: winston.format.printf(info => info.message),
    transports: [
        new winston.transports.File({ filename: 'error.log', maxsize: 1000000, maxFiles: 5 })
    ]
});

// Wrapper to mimic Flask's app.logger and inject request data
app.logger = {
    info: (msg, req = null) => {
        const client_ip = req ? req.ip.replace(/^.*:/, '') : "-";
        const user_id = (req && req.user) ? req.user.username : "-";
        accessLogger.info(`${client_ip} - ${user_id} [${getUtcAccessTimestamp()}] "${msg}" ${hostname} ${host_ip}`);
    },
    warning: (msg, req = null) => {
        const client_ip = req ? req.ip.replace(/^.*:/, '') : "-";
        const user_id = (req && req.user) ? req.user.username : "-";
        accessLogger.info(`${client_ip} - ${user_id} [${getUtcAccessTimestamp()}] "WARNING: ${msg}" ${hostname} ${host_ip}`);
    },
    error: (msg, req = null) => {
        const client_ip = req ? req.ip.replace(/^.*:/, '') : "system";
        errorLogger.error(`[${getUtcErrorTimestamp()}] [error] [client ${client_ip}] ${msg} (Host: ${hostname} ${host_ip})`);
    }
};

app.logger.info("SYSTEM_STARTUP - Server initialized");

// -------------------------
// Express App & Middleware Setup
// -------------------------
app.set('view engine', 'ejs'); // Using EJS as the template engine
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('trust proxy', true); // Useful if behind a cloud load balancer for accurate req.ip

app.use(session({
    secret: process.env.SECRET_KEY || 'default_secret',
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Context Processor Equivalent (Inject variables into all templates)
app.use((req, res, next) => {
    res.locals.host_name = hostname;
    res.locals.host_ip = host_ip;
    res.locals.current_user = req.user || null;
    res.locals.messages = req.flash();
    next();
});

// -------------------------
// Azure SQL Connection
// -------------------------
const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
        host: process.env.DB_SERVER,
        dialect: 'mssql',
        dialectOptions: {
            options: {
                encrypt: true,
                trustServerCertificate: false,
                connectTimeout: 30000 
            }
        },
        logging: false // Disable console logging for SQL queries
    }
);

// -------------------------
// Model
// -------------------------
const User = sequelize.define('User', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    username: { type: DataTypes.STRING(150), unique: true, allowNull: false },
    password: { type: DataTypes.STRING(255), allowNull: false }
}, {
    tableName: 'users',
    timestamps: false
});

// -------------------------
// Passport Login Manager
// -------------------------
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ where: { username } });
        if (!user) return done(null, false, { message: 'Invalid credentials' });
        
        const match = await bcrypt.compare(password, user.password);
        if (!match) return done(null, false, { message: 'Invalid credentials' });
        
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findByPk(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Login Required Middleware
const loginRequired = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

// -------------------------
// Routes
// -------------------------
app.get('/', (req, res) => res.redirect('/login'));

app.route('/register')
    .get((req, res) => res.render('register'))
    .post(async (req, res) => {
        const { username, password } = req.body;

        try {
            const existingUser = await User.findOne({ where: { username } });
            if (existingUser) {
                app.logger.warning(`POST /register HTTP/1.1 400 - User ${username} exists`, req);
                req.flash('error', 'User already exists');
                return res.redirect('/register');
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            await User.create({ username, password: hashedPassword });
            
            app.logger.info(`POST /register HTTP/1.1 201 - Created ${username}`, req);
            req.flash('success', 'Account created');
            res.redirect('/login');
        } catch (err) {
            app.logger.error(`POST /register HTTP/1.1 500 - Registration failed: ${err.message}`, req);
            req.flash('error', 'An error occurred during registration.');
            res.redirect('/register');
        }
    });

app.route('/login')
    .get((req, res) => res.render('login'))
    .post((req, res, next) => {
        const { username } = req.body;
        passport.authenticate('local', (err, user, info) => {
            if (err) return next(err);
            if (!user) {
                app.logger.warning(`POST /login HTTP/1.1 401 - Failed login: ${username}`, req);
                req.flash('error', info.message || 'Invalid credentials');
                return res.redirect('/login');
            }
            req.logIn(user, (err) => {
                if (err) return next(err);
                app.logger.info(`POST /login HTTP/1.1 200 - User ${username} logged in`, req);
                return res.redirect('/dashboard');
            });
        })(req, res, next);
    });

app.get('/logout', loginRequired, (req, res, next) => {
    const uname = req.user.username;
    req.logout((err) => {
        if (err) return next(err);
        app.logger.info(`GET /logout HTTP/1.1 200 - User ${uname} logged out`, req);
        res.redirect('/login');
    });
});

app.get('/dashboard', loginRequired, (req, res) => {
    res.render('dashboard', { user: req.user });
});

// -------------------------
// Execution
// -------------------------
const PORT = 80;

sequelize.sync() // Replaces db.create_all()
    .then(() => {
        app.logger.info("SYSTEM - Database tables verified");
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch((err) => {
        app.logger.error(`SYSTEM - Startup DB Error: ${err.message}`);
    });