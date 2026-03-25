import { CorsOptions } from 'cors'

export const corsConfig: CorsOptions = {
    origin: function (origin, callback) {

        const whitelist = [
            process.env.FRONTEND_URL,
            "http://localhost:5173"
        ]

        // Permitir requests sin origin (Postman, mobile apps, etc)
        if (!origin) {
            return callback(null, true)
        }

        if (whitelist.includes(origin)) {
            callback(null, true)
        } else {
            console.log("❌ CORS bloqueado:", origin)
            callback(new Error('Error de CORS'))
        }
    }
}