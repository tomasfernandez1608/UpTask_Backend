import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import User, { IUser } from '../models/User'

declare global {
    namespace Express {
        interface Request {
            user?: IUser
        }
    }
}

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {

    const bearer = req.headers.authorization

    if (!bearer) {
        return res.status(401).json({ error: 'No Autorizado' })
    }

    const [, token] = bearer.split(' ')

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { id: string }

        const user = await User.findById(decoded.id).select('_id name email')

        if (!user) {
            return res.status(401).json({ error: 'Token No Válido' })
        }

        req.user = user
        next()

    } catch (error) {
        return res.status(401).json({ error: 'Token No Válido' })
    }
}