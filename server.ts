import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db';
import { OrderStatus, PaymentStatus, UserRole } from './src/types';

dotenv.config();

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'samir_family_restaurant_super_secret_key_2026';

interface AuthRequest extends Request {
  user?: {
    id: string;
    username: string;
    name: string;
    role: UserRole;
  };
}

// Authentication Middleware
function authenticateToken(req: AuthRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Authentication token required' });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded) {
      res.status(403).json({ error: 'Invalid or expired token' });
      return;
    }
    req.user = decoded as AuthRequest['user'];
    next();
  });
}

function requireAdmin(req: AuthRequest, res: Response, next: NextFunction): void {
  if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'manager')) {
    res.status(403).json({ error: 'Admin privileges required' });
    return;
  }
  next();
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // Generate initial QRs if not yet generated
  await db.generateAllTableQRs();

  // ---------------- PUBLIC API ROUTES ----------------

  // Health check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({ status: 'ok', restaurant: db.getSettings().name });
  });

  // Get Restaurant Settings
  app.get('/api/public/settings', (req: Request, res: Response) => {
    res.json(db.getSettings());
  });

  // Get Categories
  app.get('/api/public/categories', (req: Request, res: Response) => {
    res.json(db.getCategories());
  });

  // Get Menu Items
  app.get('/api/public/menu', (req: Request, res: Response) => {
    res.json(db.getMenuItems());
  });

  // Get Active Offers
  app.get('/api/public/offers', (req: Request, res: Response) => {
    res.json(db.getOffers(true));
  });

  // Validate Table & Check active table state
  app.get('/api/public/tables/:number', (req: Request, res: Response) => {
    const tableNum = parseInt(req.params.number, 10);
    if (isNaN(tableNum)) {
      res.status(400).json({ error: 'Invalid table number' });
      return;
    }
    const table = db.getTableByNumber(tableNum);
    if (!table) {
      res.status(404).json({ error: `Table ${tableNum} is not registered in the system` });
      return;
    }
    const activeOrder = db.getActiveOrderByTable(tableNum);
    res.json({
      table,
      activeOrder: activeOrder || null
    });
  });

  // Create Order (Customer) - with strict Server-Side Price Verification
  app.post('/api/public/orders', (req: Request, res: Response) => {
    try {
      const { tableNumber, customerName, customerPhone, items, appliedCoupon, specialInstructions } = req.body;
      if (!tableNumber) {
        res.status(400).json({ error: 'Table number is required' });
        return;
      }
      if (!items || !Array.isArray(items) || items.length === 0) {
        res.status(400).json({ error: 'Cart cannot be empty' });
        return;
      }

      const order = db.createOrder({
        tableNumber: Number(tableNumber),
        customerName,
        customerPhone,
        items,
        appliedCoupon,
        specialInstructions
      });

      res.status(201).json({
        success: true,
        message: `Order #${order.orderNumber} placed successfully!`,
        order
      });
    } catch (err: any) {
      console.error('Order creation failed:', err);
      res.status(400).json({ error: err.message || 'Failed to place order' });
    }
  });

  // Track Order by ID
  app.get('/api/public/orders/:id', (req: Request, res: Response) => {
    const order = db.getOrderById(req.params.id);
    if (!order) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }
    res.json(order);
  });

  // Request Bill for Order
  app.post('/api/public/orders/:id/request-bill', (req: Request, res: Response) => {
    const order = db.requestBillForOrder(req.params.id);
    if (!order) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }
    res.json({
      success: true,
      message: `Bill requested for Table ${order.tableNumber}`,
      order
    });
  });

  // Submit Payment Confirmation
  app.post('/api/public/orders/:id/payment', (req: Request, res: Response) => {
    const { paymentMethod, paymentReference } = req.body;
    const order = db.getOrderById(req.params.id);
    if (!order) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }

    const updated = db.updateOrderPayment(order.id, {
      paymentStatus: paymentMethod === 'cash' ? 'pending' : 'verification_requested',
      paymentMethod,
      paymentReference
    });

    res.json({
      success: true,
      message: paymentMethod === 'cash' 
        ? 'Cash payment requested. Staff will collect payment at your table.' 
        : 'Payment details submitted for verification.',
      order: updated
    });
  });

  // Call Waiter / Service Request
  app.post('/api/public/waiter-requests', (req: Request, res: Response) => {
    const { tableNumber, type, customMessage } = req.body;
    if (!tableNumber || !type) {
      res.status(400).json({ error: 'Table number and request type are required' });
      return;
    }
    const table = db.getTableByNumber(Number(tableNumber));
    if (!table) {
      res.status(404).json({ error: `Table ${tableNumber} not found` });
      return;
    }

    const request = db.createWaiterRequest({
      tableNumber: Number(tableNumber),
      type,
      customMessage
    });

    res.status(201).json({
      success: true,
      message: `Staff has been notified. Someone will assist Table ${tableNumber} shortly.`,
      request
    });
  });

  // Digital Bill Data Endpoint
  app.get('/api/public/orders/:id/bill', (req: Request, res: Response) => {
    const order = db.getOrderById(req.params.id);
    if (!order) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }
    const settings = db.getSettings();
    res.json({
      restaurant: settings,
      order,
      generatedAt: new Date().toISOString()
    });
  });

  // ---------------- AUTHENTICATION ----------------

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' });
      return;
    }

    const user = db.findAdminByUsername(username);
    if (!user || !db.verifyAdminPassword(password, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }

    const tokenPayload = {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: tokenPayload
    });
  });

  app.get('/api/auth/me', authenticateToken, (req: AuthRequest, res: Response) => {
    res.json({ user: req.user });
  });

  // ---------------- KITCHEN KDS ENDPOINTS ----------------

  app.get('/api/kitchen/orders', authenticateToken, (req: AuthRequest, res: Response) => {
    // Return all non-cancelled orders from today/active
    const orders = db.getOrders().filter(o => o.status !== 'cancelled');
    res.json(orders);
  });

  app.patch('/api/kitchen/orders/:id/status', authenticateToken, (req: AuthRequest, res: Response) => {
    const { status } = req.body as { status: OrderStatus };
    if (!status) {
      res.status(400).json({ error: 'Status is required' });
      return;
    }
    const updated = db.updateOrderStatus(req.params.id, status);
    if (!updated) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }
    res.json(updated);
  });

  // ---------------- ADMIN / OWNER ENDPOINTS ----------------

  // Dashboard Stats
  app.get('/api/admin/dashboard-stats', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    res.json(db.getDashboardStats());
  });

  // Orders Management
  app.get('/api/admin/orders', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const { status, paymentStatus, tableNumber, date, startDate, endDate, search } = req.query;
    const orders = db.getOrders({
      status: status ? (status as OrderStatus) : undefined,
      paymentStatus: paymentStatus ? (paymentStatus as PaymentStatus) : undefined,
      tableNumber: tableNumber ? Number(tableNumber) : undefined,
      date: date ? String(date) : undefined,
      startDate: startDate ? String(startDate) : undefined,
      endDate: endDate ? String(endDate) : undefined,
      search: search ? String(search) : undefined
    });
    res.json(orders);
  });

  app.patch('/api/admin/orders/:id/status', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const { status } = req.body;
    const updated = db.updateOrderStatus(req.params.id, status);
    if (!updated) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }
    res.json(updated);
  });

  app.patch('/api/admin/orders/:id/payment', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const { paymentStatus, paymentMethod, paymentReference } = req.body;
    const updated = db.updateOrderPayment(req.params.id, {
      paymentStatus: paymentStatus as PaymentStatus,
      paymentMethod,
      paymentReference
    });
    if (!updated) {
      res.status(404).json({ error: 'Order not found' });
      return;
    }
    res.json(updated);
  });

  // Menu Management
  app.get('/api/admin/menu', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    res.json(db.getMenuItems());
  });

  app.post('/api/admin/menu', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    try {
      const newItem = db.addMenuItem(req.body);
      res.status(201).json(newItem);
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  app.put('/api/admin/menu/:id', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const updated = db.updateMenuItem(req.params.id, req.body);
    if (!updated) {
      res.status(404).json({ error: 'Menu item not found' });
      return;
    }
    res.json(updated);
  });

  app.delete('/api/admin/menu/:id', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const success = db.deleteMenuItem(req.params.id);
    if (!success) {
      res.status(404).json({ error: 'Menu item not found' });
      return;
    }
    res.json({ success: true });
  });

  app.patch('/api/admin/menu/:id/toggle', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const updated = db.toggleItemAvailability(req.params.id);
    if (!updated) {
      res.status(404).json({ error: 'Menu item not found' });
      return;
    }
    res.json(updated);
  });

  // Table Management & QR
  app.get('/api/admin/tables', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    res.json(db.getTables());
  });

  app.post('/api/admin/tables', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
    try {
      const newTable = await db.addTable(req.body);
      res.status(201).json(newTable);
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  app.put('/api/admin/tables/:id', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const updated = db.updateTable(req.params.id, req.body);
    if (!updated) {
      res.status(404).json({ error: 'Table not found' });
      return;
    }
    res.json(updated);
  });

  app.delete('/api/admin/tables/:id', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const success = db.deleteTable(req.params.id);
    if (!success) {
      res.status(404).json({ error: 'Table not found' });
      return;
    }
    res.json({ success: true });
  });

  app.post('/api/admin/tables/generate-all-qr', authenticateToken, requireAdmin, async (req: AuthRequest, res: Response) => {
    const origin = req.body.baseUrl || `${req.protocol}://${req.get('host')}`;
    await db.generateAllTableQRs(origin);
    res.json({ success: true, tables: db.getTables() });
  });

  // Waiter Requests Management
  app.get('/api/admin/waiter-requests', authenticateToken, (req: AuthRequest, res: Response) => {
    res.json(db.getWaiterRequests());
  });

  app.patch('/api/admin/waiter-requests/:id/status', authenticateToken, (req: AuthRequest, res: Response) => {
    const { status } = req.body;
    const updated = db.updateWaiterRequestStatus(req.params.id, status);
    if (!updated) {
      res.status(404).json({ error: 'Waiter request not found' });
      return;
    }
    res.json(updated);
  });

  // Offers Management
  app.get('/api/admin/offers', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    res.json(db.getOffers(false));
  });

  app.post('/api/admin/offers', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    try {
      const newOffer = db.createOffer(req.body);
      res.status(201).json(newOffer);
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  app.put('/api/admin/offers/:id', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const updated = db.updateOffer(req.params.id, req.body);
    if (!updated) {
      res.status(404).json({ error: 'Offer not found' });
      return;
    }
    res.json(updated);
  });

  app.delete('/api/admin/offers/:id', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const success = db.deleteOffer(req.params.id);
    if (!success) {
      res.status(404).json({ error: 'Offer not found' });
      return;
    }
    res.json({ success: true });
  });

  // Settings Management
  app.put('/api/admin/settings', authenticateToken, requireAdmin, (req: AuthRequest, res: Response) => {
    const updated = db.updateSettings(req.body);
    res.json(updated);
  });

  // ---------------- VITE / FRONTEND SERVING ----------------

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Samir Restaurant QR Ordering & Management Server running on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
