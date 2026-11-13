const { useState, useEffect, useLayoutEffect, useRef, useMemo } = React;

// Error Boundary para exibir erros de renderização
class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }
    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }
    componentDidCatch(error, info) {
        console.error('ErrorBoundary:', error, info);
    }
    render() {
        if (this.state.hasError && this.state.error) {
            return (
                <div style={{ fontFamily: 'system-ui', maxWidth: 560, margin: '2rem auto', padding: '2rem', textAlign: 'center', background: '#fef2f2', border: '2px solid #fecaca', borderRadius: 16 }}>
                    <h1 style={{ color: '#991b1b', marginBottom: '1rem' }}>Erro na aplicação</h1>
                    <p style={{ color: '#b91c1c', marginBottom: '1rem', wordBreak: 'break-word' }}>{this.state.error.message}</p>
                    <button onClick={() => this.setState({ hasError: false, error: null })} style={{ padding: '8px 16px', borderRadius: 8, background: '#dc2626', color: 'white', border: 'none', cursor: 'pointer' }}>Tentar novamente</button>
                </div>
            );
        }
        return this.props.children;
    }
}

// 🔐 Sistema de Gerenciamento de Credenciais

// Utilitários de Hash (simulação para ambiente cliente)
const CryptoUtils = {
    // Simulação de hash simples para ambiente cliente
    hashPassword: (password) => {
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            const char = password.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash).toString(16);
    },

    comparePassword: (password, hash) => {
        return CryptoUtils.hashPassword(password) === hash;
    }
};

// Regras de validação de senha
const passwordRules = {
    minLength: 8,
    maxLength: 50,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventReuse: 5,
    specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// Validador de Credenciais
class CredentialValidator {
    static validateUsername(username) {
        const errors = [];

        if (!username || username.length < 3) {
            errors.push('Nome de usuário deve ter pelo menos 3 caracteres');
        }

        if (username.length > 20) {
            errors.push('Nome de usuário deve ter no máximo 20 caracteres');
        }

        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
            errors.push('Nome de usuário deve conter apenas letras, números, _ ou -');
        }

        const reservedUsernames = ['admin', 'root', 'system', 'null', 'undefined'];
        if (reservedUsernames.includes(username.toLowerCase())) {
            errors.push('Este nome de usuário é reservado');
        }

        return { isValid: errors.length === 0, errors };
    }

    static validatePassword(password) {
        const errors = [];

        if (!password || password.length < passwordRules.minLength) {
            errors.push(`A senha deve ter pelo menos ${passwordRules.minLength} caracteres`);
        }

        if (password.length > passwordRules.maxLength) {
            errors.push(`A senha deve ter no máximo ${passwordRules.maxLength} caracteres`);
        }

        if (passwordRules.requireUppercase && !/[A-Z]/.test(password)) {
            errors.push('A senha deve conter pelo menos uma letra maiúscula');
        }

        if (passwordRules.requireLowercase && !/[a-z]/.test(password)) {
            errors.push('A senha deve conter pelo menos uma letra minúscula');
        }

        if (passwordRules.requireNumbers && !/\d/.test(password)) {
            errors.push('A senha deve conter pelo menos um número');
        }

        if (passwordRules.requireSpecialChars) {
            const specialCharsRegex = new RegExp(`[${passwordRules.specialChars.replace(/[\-\[\]{}()*+?.,\\^$|#\s]/g, '\\$&')}]`);
            if (!specialCharsRegex.test(password)) {
                errors.push('A senha deve conter pelo menos um caractere especial');
            }
        }

        return { isValid: errors.length === 0, errors };
    }

    static generatePasswordStrengthScore(password) {
        let score = 0;

        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[a-z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (new RegExp(`[${passwordRules.specialChars.replace(/[\-\[\]{}()*+?.,\\^$|#\s]/g, '\\$&')}]`).test(password)) score++;

        return Math.min(score, 5);
    }

    static checkUsernameAvailability(username, currentUserId, users) {
        return !users.some(user => user.username === username && user.id !== currentUserId);
    }
}

// Gerenciador de Usuários
// API Service para comunicar com o backend Node.js
const API_BASE_URL = `${window.location.origin}/api`;

class ApiService {
    static async request(endpoint, options = {}) {
        const token = localStorage.getItem('authToken');

        const headers = {
            'Content-Type': 'application/json',
            ...(token && { 'Authorization': `Bearer ${token}` }),
            ...options.headers
        };

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                ...options,
                headers
            });

            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                throw new Error(data.error || 'Erro na requisição');
            }

            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    }

    static async validateSession() {
        try {
            const response = await this.request('/auth/validate');
            if (response && response.user) {
                localStorage.setItem('currentUser', JSON.stringify(response.user));
                return response.user;
            }
            return null;
        } catch (error) {
            console.error('Falha na validação da sessão:', error);
            // Só limpa o cache se o erro for explicitamente de autenticação (401/403)
            // Se for erro de rede (fetch) ou servidor indisponível (503), mantemos os dados para tentar novamente
            if (error.message && (error.message.includes('401') || error.message.includes('403') || error.message.includes('não autorizado') || error.message.includes('inválido'))) {
                localStorage.removeItem('authToken');
                localStorage.removeItem('currentUser');
                localStorage.removeItem('isAuthenticated');
            }
            throw error; // Repassa o erro para o App.js tratar o "Despertar" se necessário
        }
    }

    static async login(username, password) {
        const response = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        localStorage.setItem('authToken', response.token);
        localStorage.setItem('currentUser', JSON.stringify(response.user));
        return response.user;
    }

    static async register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    static async forgotPassword(username) {
        return this.request('/auth/forgot-password', {
            method: 'POST',
            body: JSON.stringify({ username })
        });
    }

    static async updateProfile(profileData) {
        const response = await this.request('/auth/profile', {
            method: 'PUT',
            body: JSON.stringify(profileData)
        });

        localStorage.setItem('currentUser', JSON.stringify(response.user));
        return response;
    }

    static logout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
    }

    // --- Métodos de Admin ---
    static async getUsers() {
        return this.request('/auth/users', {
            method: 'GET'
        });
    }

    static async authorizeUser(userId) {
        return this.request(`/auth/users/${userId}/authorize`, {
            method: 'POST'
        });
    }

    static async toggleUserBlock(userId) {
        return this.request(`/auth/users/${userId}/block`, {
            method: 'POST'
        });
    }

    static async resetUserPassword(userId) {
        return this.request(`/auth/users/${userId}/reset-password`, {
            method: 'POST'
        });
    }

    static async deleteUser(userId) {
        return this.request(`/auth/users/${userId}`, {
            method: 'DELETE'
        });
    }

    // --- Métodos de Auditoria ---
    static async getAuditStats() {
        return this.request('/admin/audit/stats', {
            method: 'GET'
        });
    }

    static async clearAuditLogs() {
        return this.request('/admin/audit', {
            method: 'DELETE'
        });
    }

    static async getLockscreenTimeout() {
        return this.request('/settings/lockscreen-timeout', {
            method: 'GET'
        });
    }

    static async updateLockscreenTimeout(timeout) {
        return this.request('/settings/lockscreen-timeout', {
            method: 'POST',
            body: JSON.stringify({ timeout })
        });
    }

    // --- Métodos de Banners ---
    static async getBanners() {
        const token = localStorage.getItem('authToken');
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const response = await fetch(`${API_BASE_URL}/banners`, {
            headers
        });

        if (!response.ok) throw new Error('Erro ao carregar banners');
        return response.json();
    }

    static async toggleBanner(id, enabled) {
        return this.request(`/admin/banners/${id}`, {
            method: 'PUT',
            body: JSON.stringify({ enabled })
        });
    }

    static async reorderBanners(orderedBanners) {
        return this.request(`/admin/banners/reorder`, {
            method: 'PUT',
            body: JSON.stringify({ orderedBanners })
        });
    }

    static async adminFreezeBanner(id, isFrozen, freezeReason) {
        return this.request(`/admin/banners/${id}/freeze`, {
            method: 'PUT',
            body: JSON.stringify({ isFrozen, freezeReason })
        });
    }

    // --- Métodos de Banners por Usuário (Admin) ---
    static async adminGetUserBanners(userId) {
        return this.request(`/admin/users/${userId}/banners`);
    }

    static async adminToggleUserBanner(userId, bannerId, enabled) {
        return this.request(`/admin/users/${userId}/banners/${bannerId}`, {
            method: 'PUT',
            body: JSON.stringify({ enabled })
        });
    }

    static async adminResetUserBanners(userId) {
        return this.request(`/admin/users/${userId}/banners`, {
            method: 'DELETE'
        });
    }

    static async adminReorderUserBanners(userId, orderedBanners) {
        return this.request(`/admin/users/${userId}/banners/reorder`, {
            method: 'PUT',
            body: JSON.stringify({ orderedBanners })
        });
    }

    static async logEvent(action, details) {
        return this.request('/audit/log', {
            method: 'POST',
            body: JSON.stringify({ action, details })
        });
    }

    static getCurrentUser() {
        try {
            return JSON.parse(localStorage.getItem('currentUser'));
        } catch (e) {
            return null;
        }
    }
}

// Componente de Perfil do Usuário
function UserProfilePage({ user, onLogout, onCredentialsChanged, darkMode }) {
    const [isEditing, setIsEditing] = useState(false);
    const [formData, setFormData] = useState({
        name: user.name || '',
        email: user.email || '',
        username: user.username || '',
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    });
    const [errors, setErrors] = useState({});
    const [isLoading, setIsLoading] = useState(false);
    const [showPasswordFields, setShowPasswordFields] = useState(false);
    const [successMessage, setSuccessMessage] = useState('');

    const handleInputChange = (field, value) => {
        setFormData(prev => ({ ...prev, [field]: value }));

        // Limpar erro específico quando usuário começa a digitar
        if (errors[field]) {
            setErrors(prev => ({ ...prev, [field]: '' }));
        }

        // Limpar mensagem de sucesso
        if (successMessage) {
            setSuccessMessage('');
        }
    };

    const validateForm = () => {
        const newErrors = {};

        // Validar nome
        if (!formData.name.trim()) {
            newErrors.name = 'Nome é obrigatório';
        }

        // Validar email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!formData.email.trim()) {
            newErrors.email = 'Email é obrigatório';
        } else if (!emailRegex.test(formData.email)) {
            newErrors.email = 'Email inválido';
        }

        // Validar username básico
        const usernameValidation = CredentialValidator.validateUsername(formData.username);
        if (!usernameValidation.isValid) {
            newErrors.username = usernameValidation.errors[0];
        }

        // Se alterando senha
        if (showPasswordFields) {
            // Validar senha atual
            if (!formData.currentPassword) {
                newErrors.currentPassword = 'Senha atual é obrigatória';
            } else if (!CryptoUtils.comparePassword(formData.currentPassword, user.password)) {
                newErrors.currentPassword = 'Senha atual incorreta';
            }

            // Validar nova senha
            if (formData.newPassword) {
                const passwordValidation = CredentialValidator.validatePassword(formData.newPassword);
                if (!passwordValidation.isValid) {
                    newErrors.newPassword = passwordValidation.errors[0];
                }
            }

            // Validar confirmação de senha
            if (formData.newPassword !== formData.confirmPassword) {
                newErrors.confirmPassword = 'Senhas não coincidem';
            }
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) {
            return;
        }

        setIsLoading(true);

        try {
            const updates = {
                name: formData.name,
                email: formData.email,
                username: formData.username
            };

            // Se alterando senha
            if (showPasswordFields && formData.newPassword) {
                updates.newPassword = formData.newPassword;
                updates.currentPassword = formData.currentPassword;
            }

            // Atualizar usuário
            const response = await ApiService.updateProfile(updates);
            const updatedUser = response.user;

            if (updatedUser) {

                setSuccessMessage('Perfil atualizado com sucesso!');
                setIsEditing(false);
                setShowPasswordFields(false);
                setFormData(prev => ({
                    ...prev,
                    currentPassword: '',
                    newPassword: '',
                    confirmPassword: ''
                }));

                // Notificar componente pai sobre a alteração
                if (onCredentialsChanged) {
                    onCredentialsChanged(updatedUser);
                }
            } else {
                setErrors({ general: 'Erro ao atualizar perfil. Tente novamente.' });
            }
        } catch (error) {
            console.error('Erro ao atualizar perfil:', error);
            setErrors({ general: 'Erro interno. Tente novamente.' });
        } finally {
            setIsLoading(false);
        }
    };

    const handleCancel = () => {
        setIsEditing(false);
        setShowPasswordFields(false);
        setFormData({
            name: user.name || '',
            email: user.email || '',
            username: user.username || '',
            currentPassword: '',
            newPassword: '',
            confirmPassword: ''
        });
        setErrors({});
        setSuccessMessage('');
    };

    const inicial = (user.name || user.username || 'U').charAt(0).toUpperCase();
    const dataBR = (v) => new Date(v).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });

    // Campo de formulário no padrão do painel (rótulo, ícone, erro ligado por aria-describedby).
    const campo = (field, label, { type = 'text', icon, placeholder, autoComplete, wide } = {}) => {
        const id = `perfil-${field}`;
        const erro = errors[field];
        return (
            <div className={`pc-field ${wide ? 'pc-span-2' : ''}`}>
                <label htmlFor={id} className="pc-label">{label}</label>
                <div className={`pc-input ${erro ? 'is-invalid' : ''}`}>
                    {icon && <PcIcon name={icon} size={18} />}
                    <input
                        id={id}
                        type={type}
                        value={formData[field]}
                        onChange={(e) => handleInputChange(field, e.target.value)}
                        disabled={isLoading}
                        placeholder={placeholder}
                        autoComplete={autoComplete}
                        aria-invalid={!!erro}
                        aria-describedby={erro ? `${id}-erro` : undefined}
                    />
                </div>
                {erro && <p id={`${id}-erro`} className="pc-field-error">{erro}</p>}
            </div>
        );
    };

    const fatos = [
        { label: 'Nome completo', value: user.name || 'Não informado', icon: 'user' },
        { label: 'E-mail', value: user.email || 'Não informado', icon: 'mail' },
        { label: 'Usuário', value: '@' + user.username, icon: 'at', mono: true },
        { label: 'Último acesso', value: user.lastLogin ? dataBR(user.lastLogin) : 'Primeiro acesso', icon: 'clock' },
        { label: 'Senha alterada em', value: user.lastPasswordChange ? dataBR(user.lastPasswordChange) : 'Nunca alterada', icon: 'key' }
    ];

    return (
        <div className="pc-page animate-fadeInUp">
            <header className="pc-hero">
                <span className="pc-hero-avatar" aria-hidden="true">{inicial}</span>
                <div className="pc-hero-text">
                    <h1 className="pc-page-title">{user.name || user.username || 'Meu Perfil'}</h1>
                    <div className="pc-hero-meta">
                        <span className={`pc-badge ${user.role === 'admin' ? 'pc-badge--warn' : 'pc-badge--brand'}`}>
                            {user.role === 'admin' ? 'Administrador' : 'Usuário'}
                        </span>
                        <span className="pc-mono">@{user.username}</span>
                    </div>
                </div>
                <div className="pc-hero-actions">
                    {!isEditing && (
                        <button type="button" className="pc-btn pc-btn--primary" onClick={() => setIsEditing(true)}>
                            <PcIcon name="edit" size={16} />
                            Editar perfil
                        </button>
                    )}
                    <button type="button" className="pc-btn" onClick={onLogout}>
                        <PcIcon name="logout" size={16} />
                        Desconectar
                    </button>
                </div>
            </header>

            {successMessage && (
                <div className="pc-alert pc-alert--ok" role="status">
                    <PcIcon name="check" size={18} />
                    <span>{successMessage}</span>
                </div>
            )}
            {errors.general && (
                <div className="pc-alert pc-alert--error" role="alert">
                    <PcIcon name="alert" size={18} />
                    <span>{errors.general}</span>
                </div>
            )}

            {!isEditing ? (
                <section className="pc-box" aria-labelledby="perfil-dados">
                    <div className="pc-box-head">
                        <div>
                            <h2 id="perfil-dados" className="pc-box-title">Dados da conta</h2>
                            <p className="pc-box-sub">Informações que identificam você no Ecossistema.</p>
                        </div>
                    </div>
                    <dl className="pc-facts">
                        {fatos.map(f => (
                            <div key={f.label} className="pc-fact">
                                <dt><PcIcon name={f.icon} size={15} />{f.label}</dt>
                                <dd className={f.mono ? 'pc-mono' : ''} title={f.value}>{f.value}</dd>
                            </div>
                        ))}
                    </dl>
                </section>
            ) : (
                <form className="pc-box" onSubmit={handleSubmit} noValidate aria-labelledby="perfil-editar">
                    <div className="pc-box-head">
                        <div>
                            <h2 id="perfil-editar" className="pc-box-title">Editar informações</h2>
                            <p className="pc-box-sub">Revise os dados e salve para aplicar.</p>
                        </div>
                    </div>
                    <div className="pc-box-body pc-form-grid">
                        {campo('name', 'Nome completo', { icon: 'user', placeholder: 'Seu nome completo', autoComplete: 'name' })}
                        {campo('email', 'E-mail', { type: 'email', icon: 'mail', placeholder: 'seu@email.com', autoComplete: 'email' })}
                        {campo('username', 'Usuário', { icon: 'at', placeholder: 'usuario', autoComplete: 'username', wide: true })}
                    </div>

                    <div className="pc-box-body pc-box-body--sep">
                        <div className="pc-toggle-row">
                            <span className="pc-tile" style={{ '--accent': 'var(--pc-brand)' }}><PcIcon name="lock" size={18} /></span>
                            <div className="pc-toggle-text">
                                <strong id="perfil-seg">Alterar senha</strong>
                                <span>Exige a senha atual para confirmar sua identidade.</span>
                            </div>
                            <button
                                type="button"
                                role="switch"
                                aria-checked={showPasswordFields}
                                aria-labelledby="perfil-seg"
                                className={`pc-switch ${showPasswordFields ? 'is-on' : ''}`}
                                onClick={() => setShowPasswordFields(v => !v)}
                                disabled={isLoading}
                            />
                        </div>
                        {showPasswordFields && (
                            <div className="pc-form-grid" style={{ marginTop: '1.25rem' }}>
                                {campo('currentPassword', 'Senha atual', { type: 'password', icon: 'key', placeholder: 'Sua senha atual', autoComplete: 'current-password', wide: true })}
                                <div className="pc-field">
                                    {campo('newPassword', 'Nova senha', { type: 'password', icon: 'lock', placeholder: 'Mínimo 8 caracteres', autoComplete: 'new-password' })}
                                    {formData.newPassword && <PasswordStrengthIndicator password={formData.newPassword} hideErrors={!!errors.newPassword} />}
                                </div>
                                {campo('confirmPassword', 'Confirmar nova senha', { type: 'password', icon: 'lock', placeholder: 'Repita a nova senha', autoComplete: 'new-password' })}
                            </div>
                        )}
                    </div>

                    <div className="pc-box-foot">
                        <button type="button" className="pc-btn" onClick={handleCancel} disabled={isLoading}>Cancelar</button>
                        <button type="submit" className="pc-btn pc-btn--primary" disabled={isLoading}>
                            {isLoading ? <span className="pc-spin pc-spin--ink" aria-hidden="true" /> : <PcIcon name="check" size={16} />}
                            {isLoading ? 'Salvando…' : 'Salvar alterações'}
                        </button>
                    </div>
                </form>
            )}
        </div>
    );
}

// Componente de Login e Cadastro
function LoginForm({ onLogin, darkMode, wakeProgress, setWakeProgress }) {
    const [isRegistering, setIsRegistering] = useState(false);
    const [isForgotPassword, setIsForgotPassword] = useState(false);
    const [forgotPasswordMsg, setForgotPasswordMsg] = useState({ type: '', text: '' });

    // Estados do formulário
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');

    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showFirstLoginModal, setShowFirstLoginModal] = useState(false);
    const [firstLoginUser, setFirstLoginUser] = useState(null);

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        if (params.get('resetAdmin') === '1' || params.get('resetAdmin') === 'sim') {
            window.history.replaceState({}, '', window.location.pathname);
            alert('A funcionalidade de reset por URL foi depreciada no novo backend.');
        }
    }, []);

    const handleFirstLoginComplete = (updatedUser) => {
        setShowFirstLoginModal(false);
        setFirstLoginUser(null);
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('currentUser', JSON.stringify(updatedUser));
        onLogin(updatedUser);
    };

    const resetForm = () => {
        setError('');
        setUsername('');
        setPassword('');
        setName('');
        setEmail('');
        setConfirmPassword('');
    };

    const toggleMode = () => {
        setIsRegistering(!isRegistering);
        setIsForgotPassword(false);
        resetForm();
    };

    const toggleForgotPassword = () => {
        setIsForgotPassword(!isForgotPassword);
        setIsRegistering(false);
        resetForm();
        setForgotPasswordMsg({ type: '', text: '' });
    };

    const handleRegister = async () => {
        // Validação básica
        if (!name.trim()) { setError('Nome é obrigatório'); return; }
        if (!email.trim() || !/\S+@\S+\.\S+/.test(email)) { setError('Email inválido'); return; }
        if (password !== confirmPassword) { setError('As senhas não coincidem'); return; }

        const userValidation = CredentialValidator.validateUsername(username);
        if (!userValidation.isValid) { setError(userValidation.errors[0]); return; }

        const passwordValidation = CredentialValidator.validatePassword(password);
        if (!passwordValidation.isValid) { setError(passwordValidation.errors[0]); return; }

        try {
            // Criar usuário no Backend
            await ApiService.register({
                name,
                email,
                username,
                password
            });

            // Não faz login automático após registro real, exibe mensagem
            setError(''); // Limpa erros
            alert('Cadastro realizado com sucesso! Sua conta aguarda aprovação do administrador para ser ativada.');
            resetForm();
            setIsRegistering(false); // Volta para tela de login
        } catch (err) {
            setError(err.message || 'Erro ao criar conta');
        }
    };

    const handleLoginSubmit = async () => {
        try {
            const user = await ApiService.login(username, password);
            setError(''); // Limpa erros em caso de sucesso

            if (user.firstLogin) {
                setFirstLoginUser(user);
                setShowFirstLoginModal(true);
                return;
            }

            localStorage.setItem('isAuthenticated', 'true');
            onLogin(user);
        } catch (error) {
            // Lógica de Despertar do Servidor no Login Inicial
            if (error.message.includes('fetch') || error.message.includes('despertando') || (error.message && error.message.includes('sleeping'))) {
                setError('');
                setWakeProgress(1); // Inicia progresso

                let retryCount = 0;
                const maxRetries = 30;
                const retryLogin = async () => {
                    retryCount++;
                    setWakeProgress(Math.min(95, Math.floor((retryCount / maxRetries) * 100)));

                    try {
                        const user = await ApiService.login(username, password);
                        setWakeProgress(100);
                        setTimeout(() => {
                            localStorage.setItem('isAuthenticated', 'true');
                            onLogin(user);
                            setWakeProgress(0);
                        }, 600);
                    } catch (retryError) {
                        if (retryCount < maxRetries) {
                            setTimeout(retryLogin, 1000);
                        } else {
                            setWakeProgress(0);
                            setError('Servidor não respondeu a tempo. Tente novamente em instantes.');
                            setIsLoading(false);
                        }
                    }
                };
                setTimeout(retryLogin, 1000);
            } else {
                console.error('Erro no login:', error);
                setError(error.message || 'Usuário ou senha inválidos.');
            }
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        try {
            if (isRegistering) {
                await handleRegister();
            } else {
                await handleLoginSubmit();
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleForgotPasswordSubmit = async (e) => {
        e.preventDefault();
        setForgotPasswordMsg({ type: '', text: '' });
        if (!username) {
            setForgotPasswordMsg({ type: 'error', text: 'Por favor, informe seu nome de usuário.' });
            return;
        }
        setIsLoading(true);
        try {
            const res = await ApiService.forgotPassword(username);
            setForgotPasswordMsg({ type: 'success', text: res.message || 'Solicitação enviada com sucesso.' });
            setUsername('');
        } catch (err) {
            setForgotPasswordMsg({ type: 'error', text: err.message || 'Erro ao solicitar redefinição.' });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="pc-login animate-fadeIn">
            <section className="pc-login-brand" aria-label="Sobre o Ecossistema DIAAF">
                <svg className="pc-login-net" aria-hidden="true" width="420" height="420" viewBox="0 0 420 420" fill="none">
                    <g stroke="#24324C" strokeWidth="1.5">
                        <line x1="210" y1="210" x2="80" y2="90" /><line x1="210" y1="210" x2="340" y2="90" />
                        <line x1="210" y1="210" x2="60" y2="230" /><line x1="210" y1="210" x2="360" y2="230" />
                        <line x1="210" y1="210" x2="110" y2="350" /><line x1="210" y1="210" x2="320" y2="350" />
                        <line x1="80" y1="90" x2="340" y2="90" /><line x1="60" y1="230" x2="110" y2="350" /><line x1="360" y1="230" x2="320" y2="350" />
                    </g>
                    <g fill="#0D1524" stroke="#2E4A7A" strokeWidth="1.5">
                        <circle cx="210" cy="210" r="34" /><circle cx="80" cy="90" r="18" /><circle cx="340" cy="90" r="18" />
                        <circle cx="60" cy="230" r="18" /><circle cx="360" cy="230" r="18" /><circle cx="110" cy="350" r="18" /><circle cx="320" cy="350" r="18" />
                    </g>
                </svg>

                <div className="relative flex items-center gap-3">
                    <div className="pc-login-mark">
                        <img src="image/ecossistema3.png" alt="" />
                    </div>
                    <div className="flex flex-col">
                        <span className="pc-display" style={{ fontWeight: 700, fontSize: '1.125rem' }}>Ecossistema DIAAF</span>
                        <span style={{ fontSize: '.8125rem', color: '#A9B4C6' }}>Divisão de Informações e Arrecadação</span>
                    </div>
                </div>

                <div className="relative flex flex-col gap-7" style={{ maxWidth: '32.5rem' }}>
                    <h1 className="pc-login-title">Os serviços fiscais da DIAAF, em um só lugar.</h1>
                    <p className="pc-login-lead">Consulte alíquotas de ISS, gere pareceres, acompanhe processos e acesse os portais do município com uma única conta.</p>
                    <ul className="pc-login-feat">
                        <li>
                            <span className="pc-login-feat-ico" style={{ background: '#16233A', color: '#7EA2FF' }}>
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                            </span>
                            <span><strong>Consulta ISS / CNAE</strong><span>Itens da LC 001/2003 cruzados com os códigos CNAE</span></span>
                        </li>
                        <li>
                            <span className="pc-login-feat-ico" style={{ background: '#12302E', color: '#4FD1BF' }}>
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /><path d="M9 13h6M9 17h4" /></svg>
                            </span>
                            <span><strong>Pareceres e processos</strong><span>Geração de pareceres e painel de distribuição de processos</span></span>
                        </li>
                        <li>
                            <span className="pc-login-feat-ico" style={{ background: '#2A2414', color: '#F2B65A' }}>
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z" /><path d="m9 12 2 2 4-4" /></svg>
                            </span>
                            <span><strong>Acesso protegido</strong><span>Cadastros aprovados pela administração e bloqueio por inatividade</span></span>
                        </li>
                    </ul>
                </div>

                <p className="relative" style={{ margin: 0, fontSize: '.8125rem', color: '#8A96AA' }}>Prefeitura Municipal de Imperatriz — MA</p>
            </section>

            <main className="pc-login-main">
                <div className="pc-login-form">
                    <div>
                        <h2 className="pc-login-h2">
                            {isForgotPassword ? 'Recuperar senha' : (isRegistering ? 'Criar conta' : 'Entrar')}
                        </h2>
                        <p className="pc-login-sub">
                            {isForgotPassword ? 'Informe seu usuário para solicitar a redefinição.' : (isRegistering ? 'Preencha os dados para solicitar acesso.' : 'Use suas credenciais de servidor.')}
                        </p>
                    </div>

                    {wakeProgress > 0 && (
                        <div className="pc-wake" role="status">
                            <div className="pc-wake-row">
                                <span><span className="pc-wake-dot" aria-hidden="true"></span>Preparando o servidor</span>
                                <span className="pc-mono" style={{ color: 'var(--pc-teal)' }}>{wakeProgress}%</span>
                            </div>
                            <div className="pc-wake-track" aria-hidden="true">
                                <div className="pc-wake-fill" style={{ width: `${wakeProgress}%` }}></div>
                            </div>
                        </div>
                    )}

                    {isForgotPassword ? (
                        <form className="flex flex-col gap-6" onSubmit={handleForgotPasswordSubmit}>
                            <div className="pc-field">
                                <label htmlFor="forgot-username" className="pc-label">Usuário</label>
                                <div className="pc-input">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></svg>
                                    <input
                                        id="forgot-username"
                                        name="username"
                                        type="text"
                                        required
                                        autoComplete="username"
                                        placeholder="Seu usuário cadastrado"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                    />
                                </div>
                            </div>

                            {forgotPasswordMsg.text && (
                                <div className={`pc-alert ${forgotPasswordMsg.type === 'success' ? 'pc-alert--ok' : 'pc-alert--error'}`} role="alert">
                                    <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={forgotPasswordMsg.type === 'success' ? "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" : "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"} /></svg>
                                    <span>{forgotPasswordMsg.text}</span>
                                </div>
                            )}

                            <button type="submit" disabled={isLoading} className="pc-btn pc-btn--primary" style={{ minHeight: '3.125rem', fontSize: '1rem' }}>
                                {isLoading ? 'Enviando solicitação…' : 'Solicitar redefinição'}
                            </button>

                            <div style={{ height: 1, background: 'var(--pc-line)' }}></div>
                            <p style={{ margin: 0, fontSize: '.875rem', color: 'var(--pc-ink-2)' }}>
                                Lembrou a senha? <button type="button" onClick={toggleForgotPassword} className="pc-link">Voltar para o login</button>
                            </p>
                        </form>
                    ) : (
                        <form className="flex flex-col gap-6" onSubmit={handleSubmit}>
                            {isRegistering && (
                                <>
                                    <div className="pc-field">
                                        <label htmlFor="reg-name" className="pc-label">Nome completo</label>
                                        <div className="pc-input">
                                            <input
                                                id="reg-name"
                                                name="name"
                                                type="text"
                                                required
                                                autoComplete="name"
                                                placeholder="Seu nome completo"
                                                value={name}
                                                onChange={(e) => setName(e.target.value)}
                                            />
                                        </div>
                                    </div>
                                    <div className="pc-field">
                                        <label htmlFor="reg-email" className="pc-label">E-mail</label>
                                        <div className="pc-input">
                                            <input
                                                id="reg-email"
                                                name="email"
                                                type="email"
                                                required
                                                autoComplete="email"
                                                placeholder="seu@email.com"
                                                value={email}
                                                onChange={(e) => setEmail(e.target.value)}
                                            />
                                        </div>
                                    </div>
                                </>
                            )}

                            <div className="pc-field">
                                <label htmlFor="login-username" className="pc-label">Usuário</label>
                                <div className="pc-input">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></svg>
                                    <input
                                        id="login-username"
                                        name="username"
                                        type="text"
                                        required
                                        autoComplete="username"
                                        placeholder="nome.sobrenome"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                    />
                                </div>
                            </div>

                            <div className="pc-field">
                                <div className="flex items-baseline justify-between gap-3">
                                    <label htmlFor="login-password" className="pc-label">Senha</label>
                                    {!isRegistering && (
                                        <button id="forgot-password-link" type="button" onClick={toggleForgotPassword} className="pc-link" style={{ fontSize: '.875rem', fontWeight: 500 }}>
                                            Esqueci minha senha
                                        </button>
                                    )}
                                </div>
                                <div className="pc-input" style={{ paddingRight: '.375rem' }}>
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
                                    <input
                                        id="login-password"
                                        name="password"
                                        type={showPassword ? 'text' : 'password'}
                                        required
                                        autoComplete={isRegistering ? "new-password" : "current-password"}
                                        placeholder="Sua senha"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowPassword(v => !v)}
                                        className="pc-iconbtn"
                                        style={{ width: '2.25rem', height: '2.25rem', border: 0, background: 'transparent' }}
                                        aria-label={showPassword ? 'Ocultar senha' : 'Mostrar senha'}
                                        aria-pressed={showPassword}
                                    >
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                            {showPassword
                                                ? <path d="M3 3l18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.1A9.8 9.8 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6C3.9 8.4 2 12 2 12s3.5 7 10 7a9.6 9.6 0 0 0 5.4-1.6" />
                                                : <><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>}
                                        </svg>
                                    </button>
                                </div>
                            </div>

                            {isRegistering && (
                                <div className="pc-field">
                                    <label htmlFor="reg-confirm" className="pc-label">Confirmar senha</label>
                                    <div className="pc-input">
                                        <input
                                            id="reg-confirm"
                                            name="confirmPassword"
                                            type={showPassword ? 'text' : 'password'}
                                            required
                                            autoComplete="new-password"
                                            placeholder="Repita a senha"
                                            value={confirmPassword}
                                            onChange={(e) => setConfirmPassword(e.target.value)}
                                        />
                                    </div>
                                </div>
                            )}

                            {error && (
                                <div className={`pc-alert ${error.includes('bloqueada') || error.includes('Restam') ? 'pc-alert--warn' : 'pc-alert--error'}`} role="alert">
                                    <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                    <span>{error}</span>
                                </div>
                            )}

                            <button
                                type="submit"
                                disabled={isLoading || (wakeProgress > 0 && wakeProgress < 100)}
                                className="pc-btn pc-btn--primary"
                                style={{ minHeight: '3.125rem', fontSize: '1rem' }}
                            >
                                {wakeProgress > 0 ? (
                                    <>
                                        <span className="w-4 h-4 border-2 border-current rounded-full animate-spin" style={{ borderTopColor: 'transparent' }} aria-hidden="true"></span>
                                        Conectando…
                                    </>
                                ) : isLoading ? (
                                    <>
                                        <span className="w-4 h-4 border-2 border-current rounded-full animate-spin" style={{ borderTopColor: 'transparent' }} aria-hidden="true"></span>
                                        Processando…
                                    </>
                                ) : (
                                    <>
                                        {isRegistering ? 'Solicitar cadastro' : 'Entrar'}
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14M13 6l6 6-6 6" /></svg>
                                    </>
                                )}
                            </button>

                            <div style={{ height: 1, background: 'var(--pc-line)' }}></div>

                            <div className="flex flex-col gap-1.5" style={{ fontSize: '.875rem' }}>
                                {isRegistering ? (
                                    <p style={{ margin: 0, color: 'var(--pc-ink-2)' }}>
                                        Já tem acesso? <button type="button" onClick={toggleMode} className="pc-link">Voltar para o login</button>
                                    </p>
                                ) : (
                                    <p style={{ margin: 0, color: 'var(--pc-ink-2)' }}>
                                        Ainda não tem acesso? <button type="button" onClick={toggleMode} className="pc-link">Solicitar cadastro</button>
                                    </p>
                                )}
                                <p style={{ margin: 0, color: 'var(--pc-muted)', lineHeight: 1.5 }}>Novos cadastros ficam pendentes até a aprovação de um administrador.</p>
                            </div>
                        </form>
                    )}
                </div>
            </main>

            {/* Modal de Primeiro Acesso */}
            {showFirstLoginModal && firstLoginUser && (
                <FirstLoginModal
                    user={firstLoginUser}
                    onComplete={handleFirstLoginComplete}
                    darkMode={darkMode}
                />
            )}
        </div>
    );
}
// Componente de Indicador de Força da Senha
function PasswordStrengthIndicator({ password, hideErrors = false }) {
    if (!password) return null;
    const score = CredentialValidator.generatePasswordStrengthScore(password);
    const validation = CredentialValidator.validatePassword(password);
    const nivel = score <= 1 ? { t: 'Muito fraca', c: 'var(--pc-danger)' }
        : score === 2 ? { t: 'Fraca', c: 'var(--pc-danger)' }
            : score === 3 ? { t: 'Média', c: 'var(--pc-amber)' }
                : score === 4 ? { t: 'Forte', c: 'var(--pc-brand)' }
                    : { t: 'Muito forte', c: 'var(--pc-teal)' };

    return (
        <div className="pc-strength" style={{ '--tone': nivel.c }}>
            <div className="pc-strength-bars" aria-hidden="true">
                {[1, 2, 3, 4, 5].map(i => <span key={i} className={i <= score ? 'is-on' : ''} />)}
            </div>
            <span className="pc-strength-label">Força da senha: <strong>{nivel.t}</strong></span>
            {!hideErrors && validation.errors.length > 0 && (
                <ul className="pc-strength-errors">
                    {validation.errors.map((erro, i) => <li key={i}>{erro}</li>)}
                </ul>
            )}
        </div>
    );
}

// Modal de Primeiro Acesso
function FirstLoginModal({ user, onComplete, darkMode }) {
    const [formData, setFormData] = useState({
        name: user.name || '',
        email: user.email || '',
        username: user.username,
        newPassword: '',
        confirmPassword: ''
    });
    const [errors, setErrors] = useState({});
    const [isSubmitting, setIsSubmitting] = useState(false);

    const validateForm = () => {
        const newErrors = {};

        // Validar nome
        if (!formData.name.trim()) {
            newErrors.name = 'Nome é obrigatório';
        }

        // Validar username se foi alterado
        if (formData.username !== user.username) {
            const usernameValidation = CredentialValidator.validateUsername(formData.username);
            if (!usernameValidation.isValid) {
                newErrors.username = usernameValidation.errors[0];
            }
            // Verificação de disponibilidade será feita pelo backend
        }

        // Validar senha
        const passwordValidation = CredentialValidator.validatePassword(formData.newPassword);
        if (!passwordValidation.isValid) {
            newErrors.newPassword = passwordValidation.errors[0];
        }

        // Validar confirmação de senha
        if (formData.newPassword !== formData.confirmPassword) {
            newErrors.confirmPassword = 'As senhas não coincidem';
        }

        // Histórico de senhas validado no servidor

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsSubmitting(true);

        try {
            // Atualizar usuário via API
            const profileData = {
                newPassword: formData.newPassword
            };

            const response = await ApiService.updateProfile(profileData);

            onComplete(response.user || response);
        } catch (error) {
            console.error('Erro ao atualizar senha no primeiro login:', error);
            setErrors({ submit: error.message || 'Erro interno. Tente novamente.' });
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className={`max-w-md w-full mx-4 p-6 rounded-lg shadow-xl ${darkMode ? 'bg-gray-800 text-white' : 'bg-white text-gray-900'
                }`}>
                <div className="text-center mb-6">
                    <h2 className="text-2xl font-bold mb-2">🔐 Atualização de Senha</h2>
                    <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                        Por segurança, é necessário cadastrar uma nova senha.
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-4">
                    {/* Nome */}
                    <div>
                        <label className={`block text-sm font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'
                            }`}>
                            Nome Completo *
                        </label>
                        <input
                            type="text"
                            value={formData.name}
                            readOnly
                            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 ${darkMode
                                ? 'bg-gray-700 border-gray-600 text-gray-400 cursor-not-allowed'
                                : 'bg-gray-100 border-gray-300 text-gray-500 cursor-not-allowed'
                                }`}
                            placeholder="Seu nome completo"
                        />
                        {errors.name && <p className="text-red-500 text-xs mt-1">{errors.name}</p>}
                    </div>

                    {/* Email */}
                    <div>
                        <label className={`block text-sm font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'
                            }`}>
                            Email (opcional)
                        </label>
                        <input
                            type="email"
                            value={formData.email}
                            readOnly
                            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 ${darkMode
                                ? 'bg-gray-700 border-gray-600 text-gray-400 cursor-not-allowed'
                                : 'bg-gray-100 border-gray-300 text-gray-500 cursor-not-allowed'
                                }`}
                            placeholder="seu@email.com"
                        />
                    </div>

                    {/* Username */}
                    <div>
                        <label className={`block text-sm font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'
                            }`}>
                            Nome de Usuário
                        </label>
                        <input
                            type="text"
                            value={formData.username}
                            readOnly
                            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 ${darkMode
                                ? 'bg-gray-700 border-gray-600 text-gray-400 cursor-not-allowed'
                                : 'bg-gray-100 border-gray-300 text-gray-500 cursor-not-allowed'
                                }`}
                            placeholder="Seu nome de usuário"
                        />
                        {errors.username && <p className="text-red-500 text-xs mt-1">{errors.username}</p>}
                    </div>

                    {/* Nova Senha */}
                    <div>
                        <label className={`block text-sm font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'
                            }`}>
                            Nova Senha *
                        </label>
                        <input
                            type="password"
                            value={formData.newPassword}
                            onChange={(e) => setFormData({ ...formData, newPassword: e.target.value })}
                            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 ${darkMode
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                                : 'bg-white border-gray-300 text-gray-900'
                                } ${errors.newPassword ? 'border-red-500' : ''}`}
                            placeholder="Sua nova senha segura"
                        />
                        <PasswordStrengthIndicator password={formData.newPassword} darkMode={darkMode} />
                        {errors.newPassword && <p className="text-red-500 text-xs mt-1">{errors.newPassword}</p>}
                    </div>

                    {/* Confirmar Senha */}
                    <div>
                        <label className={`block text-sm font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'
                            }`}>
                            Confirmar Nova Senha *
                        </label>
                        <input
                            type="password"
                            value={formData.confirmPassword}
                            onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                            className={`w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 ${darkMode
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                                : 'bg-white border-gray-300 text-gray-900'
                                } ${errors.confirmPassword ? 'border-red-500' : ''}`}
                            placeholder="Confirme sua nova senha"
                        />
                        {errors.confirmPassword && <p className="text-red-500 text-xs mt-1">{errors.confirmPassword}</p>}
                    </div>

                    {errors.submit && (
                        <div className="text-red-500 text-sm text-center">
                            {errors.submit}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={isSubmitting}
                        className="w-full py-2 px-4 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white font-medium rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-colors"
                    >
                        {isSubmitting ? 'Salvando...' : 'Definir Credenciais'}
                    </button>
                </form>

                <div className={`mt-4 text-xs text-center ${darkMode ? 'text-gray-400' : 'text-gray-500'
                    }`}>
                    Esta configuração é obrigatória para sua segurança.
                </div>
            </div>
        </div>
    );
}

// Componente Modal de Cadastro de Usuário
function RegisterUserModal({ onClose, onUserCreated, darkMode }) {
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        username: '',
        password: '',
        confirmPassword: '',
        role: 'user'
    });
    const [errors, setErrors] = useState({});
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    const validateForm = () => {
        const newErrors = {};

        if (!formData.name.trim()) newErrors.name = 'Nome é obrigatório';
        if (!formData.email.trim()) newErrors.email = 'Email é obrigatório';
        else if (!/\S+@\S+\.\S+/.test(formData.email)) newErrors.email = 'Email inválido';

        const userValidation = CredentialValidator.validateUsername(formData.username);
        if (!userValidation.isValid) newErrors.username = userValidation.errors[0];

        const passwordValidation = CredentialValidator.validatePassword(formData.password);
        if (!passwordValidation.isValid) newErrors.password = passwordValidation.errors[0];

        if (formData.password !== formData.confirmPassword) newErrors.confirmPassword = 'As senhas não coincidem';

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsLoading(true);
        try {
            const response = await ApiService.register({
                name: formData.name,
                email: formData.email,
                username: formData.username,
                password: formData.password,
                role: formData.role
            });

            if (onUserCreated) onUserCreated(response.user || response);
            onClose();
        } catch (error) {
            console.error('Erro ao criar usuário:', error);
            setErrors(prev => ({ ...prev, general: error.message || 'Erro ao criar usuário' }));
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 p-4">
            <div className={`w-full max-w-md rounded-lg shadow-xl overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <div className={`px-6 py-4 border-b ${darkMode ? 'border-gray-700' : 'border-gray-200'} flex justify-between items-center`}>
                    <h3 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Novo Usuário</h3>
                    <button onClick={onClose} className={`text-gray-500 hover:text-gray-700 ${darkMode ? 'hover:text-gray-300' : ''}`}>
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="p-6 max-h-[80vh] overflow-y-auto custom-scrollbar">
                    {/* Campos do Formulário */}
                    <div className="space-y-4">
                        <div>
                            <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Nome Completo</label>
                            <input
                                type="text"
                                value={formData.name}
                                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                className={`mt-1 block w-full rounded-md shadow-sm px-3 py-2 border ${errors.name ? 'border-red-500' : (darkMode ? 'border-gray-600 bg-gray-700 text-white' : 'border-gray-300')}`}
                            />
                            {errors.name && <p className="text-red-500 text-xs mt-1">{errors.name}</p>}
                        </div>

                        <div>
                            <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Email</label>
                            <input
                                type="email"
                                value={formData.email}
                                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                className={`mt-1 block w-full rounded-md shadow-sm px-3 py-2 border ${errors.email ? 'border-red-500' : (darkMode ? 'border-gray-600 bg-gray-700 text-white' : 'border-gray-300')}`}
                            />
                            {errors.email && <p className="text-red-500 text-xs mt-1">{errors.email}</p>}
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Usuário</label>
                                <input
                                    type="text"
                                    value={formData.username}
                                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                                    className={`mt-1 block w-full rounded-md shadow-sm px-3 py-2 border ${errors.username ? 'border-red-500' : (darkMode ? 'border-gray-600 bg-gray-700 text-white' : 'border-gray-300')}`}
                                />
                                {errors.username && <p className="text-red-500 text-xs mt-1">{errors.username}</p>}
                            </div>
                            <div>
                                <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Perfil</label>
                                <select
                                    value={formData.role}
                                    onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                                    className={`mt-1 block w-full rounded-md shadow-sm px-3 py-2 border ${darkMode ? 'border-gray-600 bg-gray-700 text-white' : 'border-gray-300'}`}
                                >
                                    <option value="user">Usuário</option>
                                    <option value="consultor">Consultor</option>
                                    <option value="admin">Administrador</option>
                                </select>
                            </div>
                        </div>

                        <div>
                            <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Senha</label>
                            <div className="relative">
                                <input
                                    type={showPassword ? "text" : "password"}
                                    value={formData.password}
                                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                    className={`mt-1 block w-full rounded-md shadow-sm px-3 py-2 border ${errors.password ? 'border-red-500' : (darkMode ? 'border-gray-600 bg-gray-700 text-white' : 'border-gray-300')}`}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-gray-700"
                                >
                                    {showPassword ? (
                                        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                                    ) : (
                                        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.542-7a10.059 10.059 0 013.999-5.325m-2.718-2.718l14.142 14.142" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.88 9.88a3 3 0 104.24 4.24" /></svg>
                                    )}
                                </button>
                            </div>
                            {errors.password && <p className="text-red-500 text-xs mt-1">{errors.password}</p>}
                        </div>

                        <div>
                            <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Confirmar Senha</label>
                            <input
                                type="password"
                                value={formData.confirmPassword}
                                onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                                className={`mt-1 block w-full rounded-md shadow-sm px-3 py-2 border ${errors.confirmPassword ? 'border-red-500' : (darkMode ? 'border-gray-600 bg-gray-700 text-white' : 'border-gray-300')}`}
                            />
                            {errors.confirmPassword && <p className="text-red-500 text-xs mt-1">{errors.confirmPassword}</p>}
                        </div>

                        {errors.general && (
                            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
                                <span className="block sm:inline">{errors.general}</span>
                            </div>
                        )}
                    </div>

                    <div className="mt-6 flex justify-end gap-3">
                        <button
                            type="button"
                            onClick={onClose}
                            className={`px-4 py-2 rounded-md ${darkMode ? 'text-gray-300 hover:text-white hover:bg-gray-700' : 'text-gray-700 hover:text-gray-900 hover:bg-gray-100'}`}
                        >
                            Cancelar
                        </button>
                        <button
                            type="submit"
                            disabled={isLoading}
                            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
                        >
                            {isLoading ? (
                                <>
                                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                                    Salvando...
                                </>
                            ) : (
                                'Cadastrar'
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

// Componente de Gráfico de Barras Horizontal
function BarChart({ data, darkMode, title, color = 'blue', maxBars = 7 }) {
    const sortedData = [...data].sort((a, b) => b.value - a.value).slice(0, maxBars);

    if (sortedData.length === 0) {
        return (
            <div className={`p-4 rounded-lg shadow-sm ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`font-semibold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
                <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Sem dados para exibir</p>
            </div>
        );
    }

    const maxValue = Math.max(...sortedData.map(item => item.value));

    return (
        <div className={`p-4 rounded-lg shadow-sm ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
            <h3 className={`font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
            <div className="space-y-3">
                {sortedData.map((item, index) => (
                    <div key={index} className="space-y-1">
                        <div className="flex justify-between text-xs">
                            <span className={`${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{item.label}</span>
                            <span className={`font-medium ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>{item.value}</span>
                        </div>
                        <div className={`w-full rounded-full h-2 overflow-hidden ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                            <div
                                className={`h-full rounded-full transition-all duration-500 ${color === 'purple' ? 'bg-purple-500' : 'bg-blue-500'}`}
                                style={{ width: `${(item.value / maxValue) * 100}%` }}
                            ></div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// Componente de Gráfico de Barras Vertical
function VerticalBarChart({ data, darkMode, title, color = 'blue', maxBars = 7 }) {
    const sortedData = [...data].sort((a, b) => b.value - a.value).slice(0, maxBars);

    if (sortedData.length === 0) {
        return (
            <div className={`p-4 rounded-lg shadow-sm ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`font-semibold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
                <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Sem dados para exibir</p>
            </div>
        );
    }

    const maxValue = Math.max(...sortedData.map(item => item.value));

    return (
        <div className={`p-4 rounded-lg shadow-sm ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
            <h3 className={`font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
            <div className="flex items-end justify-between space-x-2 h-40 pt-4">
                {sortedData.map((item, index) => (
                    <div key={index} className="flex flex-col items-center flex-1 group relative h-full justify-end">
                        <div
                            className={`w-full max-w-[40px] rounded-t-md transition-all duration-500 relative ${color === 'purple' ? 'bg-purple-500 hover:bg-purple-600' : 'bg-blue-500 hover:bg-blue-600'}`}
                            style={{ height: `${Math.max((item.value / maxValue) * 80, 5)}%` }} // Altura mínima de 5% visual
                        >
                            {/* Tooltip flutuante ao hover */}
                            <div className={`absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap text-xs font-bold rounded px-2 py-1 pointer-events-none z-10 shadow-lg ${darkMode ? 'bg-gray-900 text-white' : 'bg-gray-800 text-white'}`}>
                                {item.value}
                            </div>
                        </div>
                        <span className={`text-[10px] mt-2 truncate w-full text-center ${darkMode ? 'text-gray-400' : 'text-gray-600'}`} title={item.label}>
                            {item.label}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
}

// Componente Gráfico de Pizza
function PieChart({ data, darkMode, title }) {
    const total = data.reduce((sum, item) => sum + item.value, 0);
    const colors = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#6366f1', '#f43f5e'];

    if (total === 0) {
        return (
            <div className={`p-4 rounded-lg shadow-sm ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                <h3 className={`font-semibold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
                <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Sem dados para exibir</p>
            </div>
        );
    }

    let currentAngle = 0;

    return (
        <div className={`p-4 rounded-lg shadow-sm ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'}`}>
            <h3 className={`font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{title}</h3>
            <div className="flex flex-col md:flex-row items-center justify-center gap-6">
                <div className="relative w-40 h-40">
                    <svg viewBox="0 0 100 100" className="transform -rotate-90 w-full h-full">
                        {data.map((item, index) => {
                            const sliceAngle = (item.value / total) * 360;
                            const x1 = 50 + 50 * Math.cos(Math.PI * currentAngle / 180);
                            const y1 = 50 + 50 * Math.sin(Math.PI * currentAngle / 180);
                            const x2 = 50 + 50 * Math.cos(Math.PI * (currentAngle + sliceAngle) / 180);
                            const y2 = 50 + 50 * Math.sin(Math.PI * (currentAngle + sliceAngle) / 180);

                            const largeArcFlag = sliceAngle > 180 ? 1 : 0;
                            const pathData = `M 50 50 L ${x1} ${y1} A 50 50 0 ${largeArcFlag} 1 ${x2} ${y2} Z`;

                            const path = (
                                <path
                                    key={index}
                                    d={pathData}
                                    fill={colors[index % colors.length]}
                                    stroke={darkMode ? '#1f2937' : '#ffffff'}
                                    strokeWidth="2"
                                />
                            );

                            currentAngle += sliceAngle;
                            return path;
                        })}
                        {data.length === 1 && (
                            <circle cx="50" cy="50" r="50" fill={colors[0]} />
                        )}
                    </svg>
                </div>

                <div className="space-y-2 max-h-40 overflow-y-auto custom-scrollbar pr-2">
                    {data.map((item, index) => (
                        <div key={index} className="flex items-center gap-2 text-xs">
                            <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: colors[index % colors.length] }}></div>
                            <span className={`${darkMode ? 'text-gray-300' : 'text-gray-700'} truncate w-24`}>{item.label}</span>
                            <span className={`font-medium ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                {item.value}
                            </span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

// Componente da Tabela de Administradores
function AdminUsersTable({ adminUsersListKey, onRefreshNeeded }) {
    const [users, setUsers] = useState([]);
    const [isLoading, setIsLoading] = useState(false);

    const loadUsers = async () => {
        setIsLoading(true);
        try {
            const data = await ApiService.getUsers();
            setUsers(Array.isArray(data) ? data : []);
        } catch (error) {
            console.error('Erro ao carregar lista completa de usuários:', error);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        loadUsers();
    }, [adminUsersListKey]);

    const handleResetPassword = async (user) => {
        if (confirm(`Resetar senha de ${user.username} para 'Mudar@123'?`)) {
            try {
                await ApiService.resetUserPassword(user.id);
                alert(`Senha de ${user.username} resetada com sucesso.`);
                if (onRefreshNeeded) onRefreshNeeded();
            } catch (err) {
                alert('Erro ao resetar senha: ' + err.message);
            }
        }
    };

    const handleToggleBlock = async (user) => {
        try {
            await ApiService.toggleUserBlock(user.id);
            if (onRefreshNeeded) onRefreshNeeded();
            else loadUsers();
        } catch (err) {
            alert('Erro ao alterar status de bloqueio: ' + err.message);
        }
    };

    const handleDelete = async (user) => {
        if (confirm(`Excluir usuário ${user.username}? Esta ação não pode ser desfeita.`)) {
            try {
                await ApiService.deleteUser(user.id);
                if (onRefreshNeeded) onRefreshNeeded();
                else loadUsers();
            } catch (err) {
                alert('Erro ao excluir usuário: ' + err.message);
            }
        }
    };

    const [filtro, setFiltro] = useState('');
    const termo = filtro.trim().toLowerCase();
    const bloqueado = (u) => u.isBlockedByAdmin === true || u.isBlockedByAdmin === 1; // SQLite devolve 1/0
    const visiveis = users.filter(u => !termo
        || (u.name || '').toLowerCase().includes(termo)
        || (u.username || '').toLowerCase().includes(termo));
    const totalBloqueados = users.filter(bloqueado).length;

    return (
        <section className="pc-box" aria-labelledby="usuarios-contas">
            <div className="pc-box-head">
                <div>
                    <h2 id="usuarios-contas" className="pc-box-title">Contas</h2>
                    <p className="pc-box-sub">
                        {users.length} {users.length === 1 ? 'usuário' : 'usuários'}
                        {totalBloqueados > 0 && ` · ${totalBloqueados} ${totalBloqueados === 1 ? 'bloqueado' : 'bloqueados'}`}
                    </p>
                </div>
                <div className="pc-input pc-input--sm pc-box-search">
                    <PcIcon name="search" size={16} />
                    <label htmlFor="usuarios-filtro" className="pc-sr-only">Filtrar contas</label>
                    <input id="usuarios-filtro" type="search" value={filtro} onChange={(e) => setFiltro(e.target.value)} placeholder="Filtrar por nome ou usuário" />
                </div>
            </div>

            {isLoading ? (
                <div className="pc-loading"><span className="pc-spin" aria-hidden="true" />Carregando usuários…</div>
            ) : visiveis.length === 0 ? (
                <div className="pc-empty">
                    <span className="pc-empty-ico"><PcIcon name="users" /></span>
                    <strong>{termo ? 'Nenhuma conta encontrada' : 'Nenhuma conta cadastrada'}</strong>
                    {termo && <span>Nada corresponde a “{filtro}”.</span>}
                </div>
            ) : (
                <ul className="pc-rows">
                    {visiveis.map(user => {
                        const isBlocked = bloqueado(user);
                        const isAdminUser = user.role === 'admin';
                        return (
                            <li key={user.id} className={`pc-row ${isBlocked ? 'is-muted' : ''}`}>
                                <span className="pc-avatar">{(user.name || user.username || '?').charAt(0).toUpperCase()}</span>
                                <div className="pc-row-main">
                                    <span className="pc-row-name">{user.name || user.username}</span>
                                    <span className="pc-row-sub pc-mono">@{user.username}</span>
                                </div>
                                <div className="pc-row-tags">
                                    <span className={`pc-badge ${isAdminUser ? 'pc-badge--warn' : 'pc-badge--muted'}`}>{isAdminUser ? 'Administrador' : 'Usuário'}</span>
                                    <span className={`pc-badge ${isBlocked ? 'pc-badge--crit' : 'pc-badge--ok'}`}>{isBlocked ? 'Bloqueado' : 'Ativo'}</span>
                                </div>
                                <div className="pc-row-actions">
                                    {!isAdminUser && (
                                        <>
                                            <button type="button" className="pc-iconbtn pc-iconbtn--sm" onClick={() => handleResetPassword(user)}
                                                aria-label={`Redefinir senha de ${user.username}`} title="Redefinir senha para Mudar@123">
                                                <PcIcon name="key" size={16} />
                                            </button>
                                            <button type="button" className="pc-iconbtn pc-iconbtn--sm" onClick={() => handleToggleBlock(user)}
                                                aria-label={isBlocked ? `Desbloquear ${user.username}` : `Bloquear ${user.username}`} title={isBlocked ? 'Desbloquear' : 'Bloquear'}>
                                                <PcIcon name={isBlocked ? 'unlock' : 'lock'} size={16} />
                                            </button>
                                            <button type="button" className="pc-iconbtn pc-iconbtn--sm pc-iconbtn--danger" onClick={() => handleDelete(user)}
                                                aria-label={`Excluir ${user.username}`} title="Excluir">
                                                <PcIcon name="trash" size={16} />
                                            </button>
                                        </>
                                    )}
                                </div>
                            </li>
                        );
                    })}
                </ul>
            )}
        </section>
    );
}

// Componente Sidebar Completo com Menu Lateral
// Ícones de traço (24×24) usados na navegação e no cabeçalho.
const PC_ICONS = {
    home: <path d="M4 5a1 1 0 0 1 1-1h5v7H4zM14 4h5a1 1 0 0 1 1 1v4h-6zM14 13h6v6a1 1 0 0 1-1 1h-5zM4 15h6v5H5a1 1 0 0 1-1-1z" />,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></>,
    briefcase: <><path d="M4 8h16v11a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z" /><path d="M9 8V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3" /></>,
    user: <><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></>,
    shield: <><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z" /><path d="m9 12 2 2 4-4" /></>,
    users: <><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0" /><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6" /></>,
    layout: <><rect x="4" y="4" width="16" height="5" rx="1" /><rect x="4" y="13" width="7" height="7" rx="1" /><rect x="15" y="13" width="5" height="7" rx="1" /></>,
    logout: <><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" /><path d="M10 17l5-5-5-5M15 12H4" /></>,
    close: <path d="M18 6 6 18M6 6l12 12" />,
    menu: <path d="M4 6h16M4 12h16M4 18h16" />,
    moon: <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" />,
    sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
    mail: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3 7 9 6 9-6" /></>,
    back: <path d="M19 12H5M11 18l-6-6 6-6" />,
    chevron: <path d="m6 9 6 6 6-6" />,
    arrowOut: <path d="M7 17 17 7M8 7h9v9" />,
    download: <path d="M12 4v11M7 10l5 5 5-5M5 20h14" />,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 2" /></>,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3" /></>,
    userPlus: <><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0" /><path d="M19 8v6M16 11h6" /></>,
    grip: <path d="M4 9h16M4 15h16" />,
    globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18" /></>,
    expand: <path d="M14 4h6v6M10 20H4v-6M20 4l-6.5 6.5M4 20l6.5-6.5" />,
    arrowRight: <path d="M5 12h14M13 6l6 6-6 6" />,
    edit: <><path d="M4 20h4L19 9l-4-4L4 16z" /><path d="m13.5 6.5 4 4" /></>,
    check: <path d="m5 12 5 5 9-10" />,
    lock: <><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></>,
    unlock: <><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 7.5-2" /></>,
    key: <><circle cx="8" cy="15" r="4" /><path d="m11 12 9-9M17 6l3 3M15 8l2 2" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    at: <><circle cx="12" cy="12" r="4" /><path d="M16 12v1.5a2.5 2.5 0 0 0 5 0V12a9 9 0 1 0-3.5 7.1" /></>,
    trash: <path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" />,
    sliders: <><path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12" /><circle cx="16" cy="6" r="2" /><circle cx="10" cy="12" r="2" /><circle cx="18" cy="18" r="2" /></>,
    rotate: <><path d="M4 12a8 8 0 1 0 2.3-5.6L4 8.7" /><path d="M4 4v4.7h4.7" /></>,
    alert: <><circle cx="12" cy="12" r="9" /><path d="M12 8v4M12 16h.01" /></>,
    help: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.2a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.5M12 16.8h.01" /></>,
    chevronLeft: <path d="m15 6-6 6 6 6" />
};

function PcIcon({ name, size = 20, className, strokeWidth = 2 }) {
    return (
        <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            {PC_ICONS[name]}
        </svg>
    );
}

// Folha de um card de grupo da Início. Em vez de um acordeão, o próprio card
// "se abre": a folha nasce recortada exatamente sobre ele (clip-path + translate,
// sem distorcer o texto) e cresce até o centro; ao fechar, volta para o card.
// O card deixa um encaixe vazio na grade enquanto a folha está aberta.
const pcReducedMotion = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

function PcGroupSheet({ groupKey, title, subtitle, accent, icon, items, renderTile, onTrack, onClose }) {
    const sheetRef = useRef(null);
    const backdropRef = useRef(null);
    const closingRef = useRef(false);
    const titleId = `folha-${groupKey}`;

    const cardEl = () => document.querySelector(`[data-group-card="${groupKey}"]`);

    // Quadros da transformação card <-> folha, medidos na hora (o card pode ter mudado de lugar).
    const frames = () => {
        const sheet = sheetRef.current;
        const card = cardEl();
        if (!sheet || !card || typeof sheet.animate !== 'function' || pcReducedMotion()) return null;
        const a = card.getBoundingClientRect();
        const b = sheet.getBoundingClientRect();
        const right = Math.max(0, b.width - a.width);
        const bottom = Math.max(0, b.height - a.height);
        return [
            { transform: `translate(${a.left - b.left}px, ${a.top - b.top}px)`, clipPath: `inset(0px ${right}px ${bottom}px 0px round 16px)` },
            { transform: 'translate(0px, 0px)', clipPath: 'inset(0px 0px 0px 0px round 20px)' }
        ];
    };

    useLayoutEffect(() => {
        const f = frames();
        if (f) {
            sheetRef.current.animate(f, { duration: 460, easing: 'cubic-bezier(.2, .85, .25, 1)' });
            backdropRef.current.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 320, easing: 'ease-out' });
        }
        sheetRef.current.querySelector('.pc-sheet-close')?.focus({ preventScroll: true });
    }, []);

    const close = (after) => {
        if (closingRef.current) return;
        closingRef.current = true;
        const done = () => {
            // Síncrono: o card precisa estar visível de novo antes de receber o foco.
            if (ReactDOM.flushSync) ReactDOM.flushSync(onClose); else onClose();
            if (after) after();
            else cardEl()?.querySelector('.pc-card-hit')?.focus({ preventScroll: true });
        };
        const f = frames();
        if (!f) return done();
        backdropRef.current.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 280, easing: 'ease-in', fill: 'forwards' });
        sheetRef.current.classList.add('is-closing');
        const anim = sheetRef.current.animate([f[1], f[0]], { duration: 340, easing: 'cubic-bezier(.4, 0, .2, 1)', fill: 'forwards' });
        anim.onfinish = done;
    };

    const activate = (item) => {
        onTrack(item.label);
        // Interno troca de tela ou abre modal: a folha sai da frente primeiro.
        if (!item.href) close(item.onSelect);
    };

    useEffect(() => {
        const onKey = (e) => {
            if (e.key === 'Escape') { e.preventDefault(); close(); return; }
            // Atalho: 1–9 aciona o serviço correspondente.
            if (/^[1-9]$/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
                const alvo = sheetRef.current?.querySelectorAll('.pc-sheet-item')[Number(e.key) - 1];
                if (alvo) { e.preventDefault(); alvo.click(); }
                return;
            }
            if (e.key === 'Tab' && sheetRef.current) {
                const focaveis = sheetRef.current.querySelectorAll('button, a[href]');
                if (!focaveis.length) return;
                const first = focaveis[0];
                const last = focaveis[focaveis.length - 1];
                if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            }
        };
        document.addEventListener('keydown', onKey);
        return () => document.removeEventListener('keydown', onKey);
    }, []);

    // Portal: a Início vive num contêiner com transform (fadeInUp), que prenderia o position: fixed.
    return ReactDOM.createPortal(
        <div className="pc-sheet-layer">
            <div ref={backdropRef} className="pc-sheet-backdrop" onClick={() => close()} />
            <div
                ref={sheetRef}
                className="pc-sheet"
                role="dialog"
                aria-modal="true"
                aria-labelledby={titleId}
                style={{ '--accent': accent }}
            >
                <div className="pc-sheet-head">
                    {renderTile(icon)}
                    <div className="pc-sheet-heading">
                        <h2 id={titleId} className="pc-sheet-title">{title}</h2>
                        <p className="pc-sheet-sub">{subtitle}</p>
                    </div>
                    <button type="button" className="pc-iconbtn pc-sheet-close" aria-label="Fechar" onClick={() => close()}>
                        <PcIcon name="close" size={18} />
                    </button>
                </div>
                <div className="pc-sheet-list">
                    {items.map((item, i) => {
                        const inner = (
                            <>
                                {renderTile(item, 18)}
                                <span className="pc-sheet-text">
                                    <span className="pc-sheet-item-title">{item.label}</span>
                                    {item.desc && <span className="pc-sheet-item-desc">{item.desc}</span>}
                                </span>
                                <span className="pc-sheet-meta">
                                    {i < 9 && <kbd className="pc-kbd" aria-hidden="true">{i + 1}</kbd>}
                                    <PcIcon name={item.href ? 'arrowOut' : 'arrowRight'} size={16} />
                                </span>
                            </>
                        );
                        const common = { className: 'pc-sheet-item', style: { '--i': i }, title: item.tag };
                        return item.href ? (
                            <a key={item.id} {...common} href={item.href} target="_blank" rel="noopener noreferrer" onClick={() => activate(item)}>
                                {inner}
                            </a>
                        ) : (
                            <button key={item.id} {...common} type="button" onClick={() => activate(item)}>
                                {inner}
                            </button>
                        );
                    })}
                </div>
                <p className="pc-sheet-hint" aria-hidden="true">
                    <kbd className="pc-kbd">1</kbd>{items.length > 1 && <>–<kbd className="pc-kbd">{Math.min(items.length, 9)}</kbd></>} abre direto · <kbd className="pc-kbd">Esc</kbd> fecha
                </p>
            </div>
        </div>,
        document.body
    );
}

// Preferência de menu recolhido (só no computador; no celular o menu é gaveta).
const lerMenuRecolhido = () => {
    try { return localStorage.getItem('pcSideCollapsed') === '1'; } catch (e) { return false; }
};

function Sidebar({ currentView, setCurrentView, currentUser, onLogout, sidebarMobileOpen, onCloseSidebar, pendingCount = 0 }) {
    const isAdmin = currentUser?.role === 'admin';
    const [collapsed, setCollapsed] = useState(lerMenuRecolhido);
    const [tip, setTip] = useState(null); // rótulo flutuante dos ícones com o menu recolhido

    const alternar = () => setCollapsed(v => {
        try { localStorage.setItem('pcSideCollapsed', v ? '0' : '1'); } catch (e) { }
        return !v;
    });

    useEffect(() => { setTip(null); }, [collapsed]);

    // Atalho "[" alterna o menu (fora de campos de texto).
    useEffect(() => {
        const onKey = (e) => {
            if (e.key !== '[' || e.ctrlKey || e.metaKey || e.altKey) return;
            const t = e.target;
            if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
            if (window.matchMedia && !window.matchMedia('(min-width: 768px)').matches) return;
            e.preventDefault();
            alternar();
        };
        document.addEventListener('keydown', onKey);
        return () => document.removeEventListener('keydown', onKey);
    }, []);

    const tipProps = (label) => collapsed ? {
        onMouseEnter: (e) => { const r = e.currentTarget.getBoundingClientRect(); setTip({ label, x: r.right, y: r.top + r.height / 2 }); },
        onMouseLeave: () => setTip(null),
        onFocus: (e) => { const r = e.currentTarget.getBoundingClientRect(); setTip({ label, x: r.right, y: r.top + r.height / 2 }); },
        onBlur: () => setTip(null)
    } : {};

    const handleNavigate = (view) => {
        setCurrentView(view);
        onCloseSidebar?.();
    };

    const menuItems = [
        { id: 'home', label: 'Início', icon: 'home' },
        { id: 'search', label: 'Consulta ISS / CNAE', icon: 'search' },
        { id: 'other-services', label: 'Serviços Internos', icon: 'briefcase' },
        { id: 'profile', label: 'Meu Perfil', icon: 'user' }
    ];

    const adminItems = [
        { id: 'admin-dashboard', label: 'Auditoria', icon: 'shield' },
        { id: 'admin-users', label: 'Usuários', icon: 'users', count: pendingCount },
        { id: 'admin-banners', label: 'Banners', icon: 'layout' }
    ];

    const renderItem = (item) => {
        const active = currentView === item.id || (item.id === 'other-services' && currentView === 'outros');
        return (
            <button
                key={item.id}
                type="button"
                onClick={() => handleNavigate(item.id)}
                className={`pc-nav-item ${active ? 'is-active' : ''}`}
                aria-current={active ? 'page' : undefined}
                aria-label={collapsed ? item.label : undefined}
                {...tipProps(item.label)}
            >
                <PcIcon name={item.icon} />
                <span className="pc-fade pc-nav-text">{item.label}</span>
                {item.count > 0 && (
                    <span className="pc-nav-count" aria-label={`${item.count} pendente${item.count === 1 ? '' : 's'}`}>{item.count}</span>
                )}
            </button>
        );
    };

    return (
        <div className={`pc-side-wrap ${collapsed ? 'is-collapsed' : ''}`}>
        <aside id="menu-lateral" className={`pc-side ${sidebarMobileOpen ? 'is-open' : ''}`} aria-label="Menu lateral">
            <div className="pc-side-brand">
                <div className="pc-side-mark">
                    <img src="image/ecossistema3.png" alt="" />
                </div>
                <div className="min-w-0 pc-fade">
                    <p className="pc-side-title">Painel DIAAF</p>
                    <p className="pc-side-sub">Ecossistema digital</p>
                </div>
                <button type="button" className="pc-iconbtn pc-side-close" onClick={onCloseSidebar} aria-label="Fechar menu">
                    <PcIcon name="close" size={18} />
                </button>
            </div>

            <nav className="pc-nav" aria-label="Principal">
                {menuItems.map(renderItem)}
            </nav>

            {isAdmin && (
                <nav className="pc-nav" aria-label="Administração">
                    <span className="pc-nav-label"><span className="pc-fade">Administração</span></span>
                    {adminItems.map(renderItem)}
                </nav>
            )}

            <div className="pc-side-user" {...tipProps(currentUser?.name || currentUser?.username || 'Usuário')}>
                <span className="pc-avatar" aria-hidden="true">{iniciaisDe(currentUser)}</span>
                <div className="min-w-0 flex-1 pc-fade">
                    <p className="pc-side-user-name">{currentUser?.name || currentUser?.username || 'Usuário'}</p>
                    <p className="pc-side-user-role">{isAdmin ? 'Administrador' : 'Usuário'}</p>
                </div>
                <button type="button" onClick={onLogout} className="pc-iconbtn pc-side-logout" style={{ border: 0, width: '2.5rem', height: '2.5rem' }} aria-label="Sair" title="Sair" tabIndex={collapsed ? -1 : undefined}>
                    <PcIcon name="logout" size={18} />
                </button>
            </div>
        </aside>

        <button
            type="button"
            className="pc-side-toggle"
            onClick={alternar}
            aria-controls="menu-lateral"
            aria-expanded={!collapsed}
            aria-label={collapsed ? 'Expandir menu' : 'Recolher menu'}
            title={`${collapsed ? 'Expandir' : 'Recolher'} menu  [`}
        >
            <PcIcon name="chevronLeft" size={14} strokeWidth={2.5} />
        </button>

        {collapsed && tip && (
            <span className="pc-side-tip" role="tooltip" style={{ left: tip.x + 10, top: tip.y }}>{tip.label}</span>
        )}
        </div>
    );
}

// ==================== CENTRAL DE AUDITORIA: VISUALIZAÇÃO ====================
// Paleta do Painel Cívico, validada com scripts/validate_palette.js contra as
// superfícies dos cards (#FFFFFF claro / #121925 escuro). Slots categóricos
// azul da marca + laranja passam em todos os gates nos dois temas (CVD ΔE 30,1
// claro / 27,6 escuro). No escuro a série usa #6B8FF0: o azul de texto
// (#7EA2FF) sai da faixa de luminosidade para marcas de gráfico.
// Rampas sequenciais de um só tom, monotônicas em L (OKLab) nos dois temas.
//
// Decisão de encoding: sucesso e falha NÃO são codificados por cor em gráfico.
// O validador reprovou o par status good↔critical em ΔE 4,1 sob deuteranopia —
// é a armadilha verde/vermelho. As séries são de identidade (azul/laranja) e as
// cores de status aparecem só onde há ícone + rótulo junto, nunca sozinhas.
const VIZ = {
    light: {
        surface: '#FFFFFF',
        s1: '#1F4FD8',          // slot categórico 1 — azul da marca
        s2: '#eb6834',          // slot categórico 2 — laranja
        grid: '#E6EAF0',
        axis: '#B9C3D3',
        ink: '#0D1524',
        muted: '#566275',
        // rampa sequencial azul, clara→escura (monotônica, verificada)
        ramp: ['#EEF2FD', '#D3DEFB', '#A9BEF6', '#7D9CF0', '#4F78E6', '#1F4FD8', '#163A9E'],
        good: '#0B7A6F', warning: '#94580A', critical: '#B42318'
    },
    dark: {
        surface: '#121925',
        s1: '#6B8FF0',
        s2: '#d95926',
        grid: '#26334A',
        axis: '#3A4A66',
        ink: '#EEF2F8',
        muted: '#9AA6B9',
        // no tema escuro o "quase zero" recua para a superfície: rampa escura→clara
        ramp: ['#1A2233', '#1B2B4F', '#22397A', '#2D4EA8', '#4469D6', '#6B8FF0', '#A3BBF8'],
        good: '#4FD1BF', warning: '#F2B65A', critical: '#FF8A80'
    }
};

const vizPal = (darkMode) => darkMode ? VIZ.dark : VIZ.light;

// --- Derivações sobre o histórico de auditoria ---
const AUDIT_RANGES = [
    { id: '24h', label: '24 h', horas: 24, buckets: 24, passo: 'hora' },
    { id: '7d', label: '7 dias', horas: 24 * 7, buckets: 7, passo: 'dia' },
    { id: '30d', label: '30 dias', horas: 24 * 30, buckets: 30, passo: 'dia' },
    { id: 'all', label: 'Tudo', horas: null, buckets: 30, passo: 'dia' }
];

const ehFalha = (e) => e?.success === false || /fail/i.test(e?.action || '');
const ehLogin = (e) => e?.action === 'login_success';
const ehServico = (e) => e?.action === 'banner_clicked' || e?.type === 'banner';

function janelaAuditoria(eventos, rangeId, agora = Date.now()) {
    const r = AUDIT_RANGES.find(x => x.id === rangeId) || AUDIT_RANGES[1];
    if (!r.horas) return { inicio: 0, fim: agora, range: r };
    const ms = r.horas * 3600 * 1000;
    return { inicio: agora - ms, fim: agora, range: r };
}

function agrupaPorTempo(eventos, rangeId, agora = Date.now()) {
    const { inicio, fim, range } = janelaAuditoria(eventos, rangeId, agora);
    const base = range.horas ? inicio : (eventos.length
        ? Math.min(...eventos.map(e => new Date(e.timestamp).getTime()))
        : agora - 30 * 24 * 3600 * 1000);
    const largura = Math.max(1, (fim - base) / range.buckets);
    const bins = Array.from({ length: range.buckets }, (_, i) => ({
        t0: base + i * largura, t1: base + (i + 1) * largura, total: 0, falhas: 0
    }));
    eventos.forEach(e => {
        const t = new Date(e.timestamp).getTime();
        if (isNaN(t) || t < base || t > fim) return;
        const i = Math.min(bins.length - 1, Math.floor((t - base) / largura));
        bins[i].total++;
        if (ehFalha(e)) bins[i].falhas++;
    });
    return { bins, passo: range.passo };
}

// Mapa dia-da-semana × hora: revela janelas de uso e acesso fora de expediente.
function mapaCalor(eventos) {
    const grade = Array.from({ length: 7 }, () => new Array(24).fill(0));
    eventos.forEach(e => {
        const d = new Date(e.timestamp);
        if (isNaN(d.getTime())) return;
        grade[d.getDay()][d.getHours()]++;
    });
    return grade;
}

function ranking(eventos, chave, limite = 6) {
    const acc = {};
    eventos.forEach(e => {
        const k = typeof chave === 'function' ? chave(e) : e[chave];
        if (!k) return;
        acc[k] = (acc[k] || 0) + 1;
    });
    return Object.entries(acc).sort((a, b) => b[1] - a[1]).slice(0, limite);
}

const compacto = (n) => n >= 1e6 ? (n / 1e6).toFixed(1).replace('.0', '') + 'M'
    : n >= 1e4 ? (n / 1e3).toFixed(1).replace('.0', '') + 'K'
        : String(n);

// --- Componentes de gráfico (SVG inline; sem biblioteca externa) ---

// Sparkline do stat tile: 12 pontos, traço fino, sem eixos. Contexto, não leitura.
function VizSparkline({ pontos, cor, largura = 108, altura = 30 }) {
    if (!pontos || pontos.length < 2) return null;
    const max = Math.max(...pontos, 1);
    const passo = largura / (pontos.length - 1);
    const y = v => altura - 2 - (v / max) * (altura - 4);
    const d = pontos.map((v, i) => `${i ? 'L' : 'M'}${(i * passo).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
    const area = `${d} L${largura},${altura} L0,${altura} Z`;
    return (
        <svg className="viz-spark" viewBox={`0 0 ${largura} ${altura}`} width={largura} height={altura} aria-hidden="true">
            <path d={area} fill={cor} opacity="0.1" />
            <path d={d} fill="none" stroke={cor} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
            <circle cx={largura} cy={y(pontos[pontos.length - 1])} r="3" fill={cor} />
        </svg>
    );
}

function VizStatTile({ rotulo, valor, delta, serie, cor, nota, statusIcone, statusCor }) {
    const sinal = delta > 0 ? '+' : '';
    return (
        <div className="viz-tile">
            <p className="viz-tile-label">{rotulo}</p>
            <div className="viz-tile-row">
                <span className="viz-tile-value" style={statusCor ? { color: statusCor } : undefined}>
                    {statusIcone}{compacto(valor)}
                </span>
                {serie && <VizSparkline pontos={serie} cor={cor} />}
            </div>
            <p className="viz-tile-foot">
                {delta !== null && delta !== undefined && (
                    <span className="viz-delta" style={{ color: cor }}>{sinal}{delta}%</span>
                )}
                {nota}
            </p>
        </div>
    );
}

// Colunas de atividade. Série ÚNICA — por isso sem legenda: o título já diz o
// que está plotado. Rótulo direto só no pico (nunca um número por coluna).
function VizTimeline({ bins, passo, pal }) {
    const W = 720, H = 200, padL = 38, padR = 10, padT = 16, padB = 26;
    const max = Math.max(1, ...bins.map(b => b.total));
    const banda = (W - padL - padR) / bins.length;
    const largura = Math.min(24, banda - 4);
    const y = v => padT + (1 - v / max) * (H - padT - padB);
    const ticks = [0, Math.round(max / 2), max].filter((v, i, a) => a.indexOf(v) === i);
    const iPico = bins.reduce((m, b, i) => b.total > bins[m].total ? i : m, 0);
    const rotuloData = (t) => {
        const d = new Date(t);
        return passo === 'hora'
            ? String(d.getHours()).padStart(2, '0') + 'h'
            : d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' });
    };

    return (
        <svg className="viz-svg" viewBox={`0 0 ${W} ${H}`} role="img"
            aria-label={`Atividade por ${passo}. Pico de ${bins[iPico].total} eventos.`}>
            {ticks.map(t => (
                <g key={t}>
                    <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} stroke={pal.grid} strokeWidth="1" />
                    <text x={padL - 8} y={y(t) + 4} textAnchor="end" className="viz-tick" fill={pal.muted}>{t}</text>
                </g>
            ))}
            {bins.map((b, i) => {
                const x = padL + i * banda + (banda - largura) / 2;
                const h = Math.max(b.total > 0 ? 2 : 0, (H - padT - padB) * (b.total / max));
                return (
                    <g key={i} className="viz-col">
                        <rect x={padL + i * banda} y={padT} width={banda} height={H - padT - padB} fill="transparent" />
                        <rect x={x} y={y(b.total)} width={largura} height={h} rx="4"
                            fill={i === iPico ? pal.s1 : pal.s1} opacity={i === iPico ? 1 : 0.55} />
                        <title>{`${rotuloData(b.t0)} — ${b.total} evento${b.total === 1 ? '' : 's'}${b.falhas ? `, ${b.falhas} com falha` : ''}`}</title>
                    </g>
                );
            })}
            {/* rótulo direto apenas no pico */}
            <text x={padL + iPico * banda + banda / 2} y={y(bins[iPico].total) - 6}
                textAnchor="middle" className="viz-peak" fill={pal.ink}>{bins[iPico].total}</text>
            <line x1={padL} x2={W - padR} y1={H - padB} y2={H - padB} stroke={pal.axis} strokeWidth="1" />
            {bins.map((b, i) => (i % Math.ceil(bins.length / 8) === 0) && (
                <text key={i} x={padL + i * banda + banda / 2} y={H - padB + 16}
                    textAnchor="middle" className="viz-tick" fill={pal.muted}>{rotuloData(b.t0)}</text>
            ))}
        </svg>
    );
}

// Mapa de calor dia × hora. Magnitude → rampa de UM matiz (nunca arco-íris).
function VizHeatmap({ grade, pal }) {
    const dias = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
    const max = Math.max(1, ...grade.flat());
    const cor = v => v === 0 ? 'transparent' : pal.ramp[Math.min(pal.ramp.length - 1, Math.ceil((v / max) * (pal.ramp.length - 1)))];
    return (
        <div className="viz-heat">
            <div className="viz-heat-grid">
                {grade.map((linha, d) => (
                    <React.Fragment key={d}>
                        <span className="viz-heat-day">{dias[d]}</span>
                        {linha.map((v, h) => (
                            <span key={h} className="viz-heat-cell"
                                style={{ backgroundColor: cor(v), borderColor: v === 0 ? pal.grid : 'transparent' }}
                                title={`${dias[d]}, ${String(h).padStart(2, '0')}h — ${v} evento${v === 1 ? '' : 's'}`} />
                        ))}
                    </React.Fragment>
                ))}
                <span></span>
                {Array.from({ length: 24 }, (_, h) => (
                    <span key={h} className="viz-heat-hour">{h % 6 === 0 ? String(h).padStart(2, '0') : ''}</span>
                ))}
            </div>
            <div className="viz-scale">
                <span className="viz-tick-txt">0</span>
                {pal.ramp.map((c, i) => <span key={i} className="viz-scale-step" style={{ backgroundColor: c }} />)}
                <span className="viz-tick-txt">{max}</span>
            </div>
        </div>
    );
}

// Barras de ranking. Categorias nominais → UMA cor para todas as barras (uma
// rampa por valor duplicaria o comprimento em matiz). Valor rotulado na ponta,
// então nenhum número fica preso ao tooltip.
function VizRankBars({ dados, cor, pal, vazio }) {
    if (!dados.length) return <p className="viz-empty">{vazio}</p>;
    const max = Math.max(...dados.map(d => d[1]));
    return (
        <ul className="viz-rank">
            {dados.map(([nome, valor]) => (
                <li key={nome} className="viz-rank-row">
                    <span className="viz-rank-name" title={nome}>{nome}</span>
                    <span className="viz-rank-track" style={{ backgroundColor: pal.grid }}>
                        <span className="viz-rank-fill" style={{ width: `${(valor / max) * 100}%`, backgroundColor: cor }} />
                    </span>
                    <span className="viz-rank-val">{valor}</span>
                </li>
            ))}
        </ul>
    );
}

// ==================== PAINEL DE CONTROLE DE BANNERS ====================
// Paleta de acentos do mosaico. A cor entra apenas como identidade do serviço
// (ícone, halo e foco) — a superfície do card permanece neutra.
const MOSAIC_ACCENTS = {
    blue: { light: '#2563eb', dark: '#60a5fa' },
    indigo: { light: '#4f46e5', dark: '#818cf8' },
    violet: { light: '#7c3aed', dark: '#a78bfa' },
    fuchsia: { light: '#c026d3', dark: '#e879f9' },
    rose: { light: '#e11d48', dark: '#fb7185' },
    red: { light: '#dc2626', dark: '#f87171' },
    amber: { light: '#d97706', dark: '#fbbf24' },
    green: { light: '#16a34a', dark: '#4ade80' },
    emerald: { light: '#059669', dark: '#34d399' },
    cyan: { light: '#0891b2', dark: '#22d3ee' },
    slate: { light: '#475569', dark: '#94a3b8' }
};

const mosaicAccent = (accent, darkMode) =>
    (MOSAIC_ACCENTS[accent] || MOSAIC_ACCENTS.blue)[darkMode ? 'dark' : 'light'];

const iniciaisDe = (user) =>
    user?.name?.substring(0, 2).toUpperCase() || user?.username?.substring(0, 2).toUpperCase() || 'AD';

// Agrupamento da Início. A ordem dentro de cada seção continua sendo a do
// admin (drag & drop); um banner fora destas listas cai em "Outros serviços".
const HOME_SECTIONS = [
    { id: 'fiscal', title: 'Fiscal e tributário', keys: ['pareceres', 'processos', 'painel-distribuicao', 'nfse-nacional', 'receita'] },
    { id: 'municipio', title: 'Município e portais', keys: ['dte', 'diario-oficial', 'arrecadacao', 'entes', 'empresa-facil', 'biblioteca'] }
];

// Coluna de dados.json com a descrição do item da lista de serviços (CTM).
const CAMPO_ITEM_LC = 'Descrição item da lista da Lei Complementar nº 001/2003 - CTM';

// Rótulo da trilha no cabeçalho de cada tela.
const VIEW_TITLES = {
    profile: 'Meu Perfil',
    search: 'Consulta ISS / CNAE',
    outros: 'Serviços Internos',
    'other-services': 'Serviços Internos',
    'admin-dashboard': 'Auditoria',
    'admin-users': 'Usuários',
    'admin-banners': 'Banners'
};

const dataPorExtenso = () => {
    const s = new Date().toLocaleDateString('pt-BR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
    return s.charAt(0).toUpperCase() + s.slice(1);
};

const saudacao = () => {
    const h = new Date().getHours();
    return h < 12 ? 'Bom dia' : h < 18 ? 'Boa tarde' : 'Boa noite';
};

// Config estática dos banners (UI, cores, links)
const BANNER_STATIC = {
    'pareceres': {
        label: 'Gerador de Pareceres',
        menu: 'home',
        accent: 'emerald',
        size: 'std',
        description: 'Gere pareceres fiscais automaticamente',
        icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        href: 'https://opinion-factory-production.up.railway.app/',
        light: 'from-emerald-50 to-teal-50 border-emerald-400 hover:border-emerald-500',
        dark: 'from-emerald-900/50 to-teal-900/50 border-emerald-500/30 hover:border-emerald-500',
        iconLight: 'bg-white text-emerald-600 shadow-md',
        iconDark: 'bg-emerald-500/20 text-emerald-400',
        hoverBg: { light: 'bg-emerald-600', dark: 'bg-white' }
    },
    'processos': {
        label: 'Análise de Processos',
        menu: 'home',
        accent: 'violet',
        size: 'std',
        description: 'Visualize e analise processos fiscais',
        icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        href: 'https://reportterra-diaaf.up.railway.app/login',
        light: 'from-violet-50 to-indigo-50 border-violet-400 hover:border-violet-500',
        dark: 'from-violet-900/50 to-indigo-900/50 border-violet-500/30 hover:border-violet-500',
        iconLight: 'bg-white text-violet-600 shadow-md',
        iconDark: 'bg-violet-500/20 text-violet-400',
        hoverBg: { light: 'bg-violet-600', dark: 'bg-white' }
    },
    'painel-distribuicao': {
        label: 'Painel de Distribuição',
        menu: 'home',
        accent: 'amber',
        size: 'std',
        description: 'Acesse o Painel de Distribuição de Processos',
        icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        href: 'https://planilha-magica.up.railway.app/',
        light: 'from-amber-50 to-orange-50 border-amber-400 hover:border-amber-500',
        dark: 'from-amber-900/50 to-orange-900/50 border-amber-500/30 hover:border-amber-500',
        iconLight: 'bg-white text-amber-600 shadow-md',
        iconDark: 'bg-amber-500/20 text-amber-400',
        hoverBg: { light: 'bg-amber-600', dark: 'bg-white' }
    },
    'nfse-nacional': {
        label: 'Gestão da NFS-e',
        menu: 'home',
        accent: 'cyan',
        size: 'std',
        description: 'Acesso exclusivo aos servidores para controle e painel do sistema nacional',
        imageIcon: 'image/nfs-e.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        href: 'https://www.nfse.gov.br/PainelMunicipal/Login?ReturnUrl=%2fPainelMunicipal',
        light: 'from-cyan-50 to-sky-50 border-cyan-400 hover:border-cyan-500',
        dark: 'from-cyan-900/50 to-sky-900/50 border-cyan-500/30 hover:border-cyan-500',
        iconLight: 'bg-white text-cyan-600 shadow-md',
        iconDark: 'bg-cyan-500/20 text-cyan-400',
        hoverBg: { light: 'bg-cyan-600', dark: 'bg-white' }
    },
    'diario-oficial': {
        label: 'Diário Oficial',
        menu: 'home',
        accent: 'slate',
        size: 'tall',
        description: 'Publicações do Diário Oficial de Imperatriz',
        imageIcon: 'image/brasao.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        href: 'https://diariofacil-itz.up.railway.app/',
        light: 'from-slate-50 to-gray-50 border-slate-400 hover:border-slate-500',
        dark: 'from-slate-900/50 to-gray-900/50 border-slate-500/30 hover:border-slate-500',
        iconLight: 'bg-white text-slate-600 shadow-md',
        iconDark: 'bg-slate-500/20 text-slate-400',
        hoverBg: { light: 'bg-slate-600', dark: 'bg-white' }
    },
    'dte': {
        label: 'Prefeitura Moderna',
        menu: 'home',
        accent: 'rose',
        size: 'hero',
        description: 'O seu portal centralizado para serviços e tributos municipais',
        imageIcon: 'image/bauhaus.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        isModal: true,
        modalId: 'dte',
        href: 'https://imperatriz-ma.prefeituramoderna.com.br/dte/index.php?',
        light: 'from-rose-50 to-pink-50 border-rose-400 hover:border-rose-500',
        dark: 'from-rose-900/50 to-pink-900/50 border-rose-500/30 hover:border-rose-500',
        iconLight: 'bg-white text-rose-600 shadow-md',
        iconDark: 'bg-rose-500/20 text-rose-400',
        hoverBg: { light: 'bg-rose-600', dark: 'bg-white' }
    },
    'arrecadacao': {
        label: 'Transparência',
        menu: 'home',
        accent: 'fuchsia',
        size: 'std',
        description: 'Acompanhe as contas públicas do município',
        imageIcon: 'image/brasao.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        href: 'http://scpi3.adtrcloud.com.br:8079/transparencia/',
        light: 'from-fuchsia-50 to-pink-50 border-fuchsia-400 hover:border-fuchsia-500',
        dark: 'from-fuchsia-900/50 to-pink-900/50 border-fuchsia-500/30 hover:border-fuchsia-500',
        iconLight: 'bg-white text-fuchsia-600 shadow-md',
        iconDark: 'bg-fuchsia-500/20 text-fuchsia-400',
        hoverBg: { light: 'bg-fuchsia-600', dark: 'bg-white' }
    },
    'receita': {
        label: 'Arrecadação',
        menu: 'home',
        accent: 'green',
        size: 'std',
        description: 'Painel gerencial de indicadores tributários',
        icon: 'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
        href: 'https://arrec-itz.up.railway.app/',
        light: 'from-green-50 to-lime-50 border-green-200 hover:border-green-400',
        dark: 'from-green-900/50 to-lime-900/50 border-green-500/30 hover:border-green-500',
        iconLight: 'bg-white text-green-600 shadow-md',
        iconDark: 'bg-green-500/20 text-green-400',
        hoverBg: { light: 'bg-green-600', dark: 'bg-white' }
    },
    'entes': {
        label: 'Entes Federados',
        menu: 'home',
        accent: 'indigo',
        size: 'std',
        description: 'Acesso aos Entes Federados',
        imageIcon: 'image/entes.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        href: 'https://www10.receita.fazenda.gov.br/login/publico/bemvindo/',
        light: 'from-blue-50 to-indigo-50 border-blue-200 hover:border-blue-400',
        dark: 'from-blue-900/50 to-indigo-900/50 border-blue-500/30 hover:border-blue-500',
        iconLight: 'bg-white text-blue-600 shadow-md',
        iconDark: 'bg-blue-500/20 text-blue-400',
        hoverBg: { light: 'bg-blue-600', dark: 'bg-white' }
    },
    'empresa-facil': {
        label: 'Empresa Fácil',
        menu: 'home',
        accent: 'red',
        size: 'std',
        description: 'Acesso Rápido Empresa Fácil MA',
        imageIcon: 'image/ma.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        href: 'https://autenticacao.empresafacil.ma.gov.br/',
        light: 'from-red-50 to-rose-50 border-red-200 hover:border-red-400',
        dark: 'from-red-900/50 to-rose-900/50 border-red-500/30 hover:border-red-500',
        iconLight: 'bg-white text-red-600 shadow-md',
        iconDark: 'bg-red-500/20 text-red-400',
        hoverBg: { light: 'bg-red-600', dark: 'bg-white' }
    },
    'biblioteca': {
        label: 'Biblioteca',
        menu: 'home',
        accent: 'amber',
        size: 'wide',
        description: 'Acervo de legislação, normas e documentos municipais',
        icon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
        light: 'from-amber-50 to-yellow-50 border-amber-200 hover:border-amber-300',
        dark: 'from-amber-900/50 to-yellow-900/50 border-amber-500/30 hover:border-amber-500',
        iconLight: 'bg-white text-amber-600 shadow-md',
        iconDark: 'bg-amber-500/20 text-amber-400',
        hoverBg: { light: 'bg-amber-500', dark: 'bg-white' },
        isModal: true,
        modalId: 'biblioteca'
    },
    // --- Outros Serviços ---
    'sistema-ponto': {
        label: 'Sistema de Ponto',
        menu: 'outros',
        accent: 'blue',
        description: 'Acesse o sistema de registro de ponto eletrônico',
        href: 'https://imperatriz.ma.gov.br/sistema-de-ponto/entrar/',
        icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
        light: 'from-blue-50 to-indigo-50 border-blue-400 hover:border-blue-500',
        dark: 'from-blue-900/40 to-indigo-900/40 border-blue-500/30 hover:border-blue-400',
        iconLight: 'bg-blue-100 text-blue-600',
        iconDark: 'bg-blue-500/20 text-blue-400'
    },
    'contra-cheque': {
        label: 'Contra-cheque',
        menu: 'outros',
        accent: 'emerald',
        description: 'Consulte e emita seus contra-cheques mensais',
        href: 'https://servicos.imperatriz.ma.gov.br/portaldoservidor/login.php',
        icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        light: 'from-emerald-50 to-teal-50 border-emerald-400 hover:border-emerald-500',
        dark: 'from-emerald-900/40 to-teal-900/40 border-emerald-500/30 hover:border-emerald-400',
        iconLight: 'bg-emerald-100 text-emerald-600',
        iconDark: 'bg-emerald-500/20 text-emerald-400'
    },
    'justificativas-ponto': {
        label: 'Justificativas de Ponto',
        menu: 'outros',
        accent: 'amber',
        description: 'Acesso via INTRANET sefazgo',
        href: 'https://protocolo.imperatriz.ma.gov.br/menu',
        icon: 'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z',
        light: 'from-amber-50 to-orange-50 border-amber-400 hover:border-amber-500',
        dark: 'from-amber-900/40 to-orange-900/40 border-amber-500/30 hover:border-amber-400',
        iconLight: 'bg-amber-100 text-amber-600',
        iconDark: 'bg-amber-500/20 text-amber-400'
    },
    // --- Sub-Banners DTE ---
    'dte-portal': {
        label: 'Terra Cloud',
        menu: 'dte-sub',
        description: 'Acesse o portal central de serviços municipais',
        href: 'https://imperatriz-ma.prefeituramoderna.cloud/#/',
        icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6',
        light: 'from-rose-50 to-pink-50 border-rose-200 hover:border-rose-300', dark: 'from-rose-900/40 to-pink-900/40 border-rose-500/30 hover:border-rose-400', iconLight: 'bg-rose-100 text-rose-600', iconDark: 'bg-rose-500/20 text-rose-400'
    },
    'dte-meuiss': {
        label: 'Meu ISS',
        menu: 'dte-sub',
        description: 'Portal do contribuinte para serviços de ISS',
        href: 'https://imperatriz-ma.prefeituramoderna.com.br/meuiss_new/',
        icon: 'M9 14l6-6m-5.5.5h.01m4.99 5h.01M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5',
        light: 'from-pink-50 to-fuchsia-50 border-pink-200 hover:border-pink-300', dark: 'from-pink-900/40 to-fuchsia-900/40 border-pink-500/30 hover:border-pink-400', iconLight: 'bg-pink-100 text-pink-600', iconDark: 'bg-pink-500/20 text-pink-400'
    },
    'dte-nfe': {
        label: 'NFS-e / Nota Fiscal',
        menu: 'dte-sub',
        description: 'Consulta de notas fiscais eletrônicas',
        href: 'https://imperatriz-ma.prefeituramoderna.com.br/meuiss_new/nfe/',
        icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        light: 'from-fuchsia-50 to-purple-50 border-fuchsia-200 hover:border-fuchsia-300', dark: 'from-fuchsia-900/40 to-purple-900/40 border-fuchsia-500/30 hover:border-fuchsia-400', iconLight: 'bg-fuchsia-100 text-fuchsia-600', iconDark: 'bg-fuchsia-500/20 text-fuchsia-400'
    },
    'dte-iptu': {
        label: 'Protocolo',
        menu: 'dte-sub',
        description: 'Acompanhe e gerencie processos administrativos',
        href: 'https://imperatriz-ma.prefeituramoderna.com.br/meuiptu/protocolo-servidor/index.php',
        icon: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-2 10v-5a1 1 0 00-1-1h-2a1 1 0 00-1 1v5m-4 0h6',
        light: 'from-purple-50 to-violet-50 border-purple-200 hover:border-purple-300', dark: 'from-purple-900/40 to-violet-900/40 border-purple-500/30 hover:border-purple-400', iconLight: 'bg-purple-100 text-purple-600', iconDark: 'bg-purple-500/20 text-purple-400'
    },
    'dte-meuiptu': {
        label: 'Meu IPTU',
        menu: 'dte-sub',
        description: 'Consulte e gerencie o seu IPTU municipal',
        href: 'https://imperatriz-ma.prefeituramoderna.com.br/meuiptu/',
        icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6',
        light: 'from-violet-50 to-indigo-50 border-violet-200 hover:border-violet-300', dark: 'from-violet-900/40 to-indigo-900/40 border-violet-500/30 hover:border-violet-400', iconLight: 'bg-violet-100 text-violet-600', iconDark: 'bg-violet-500/20 text-violet-400'
    },
    'dte-login': {
        label: 'DTE - Domicílio Tributário',
        menu: 'dte-sub',
        description: 'Acesse seu domicílio tributário eletrônico',
        href: 'https://imperatriz-ma.prefeituramoderna.com.br/dte/?route=login-main',
        icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
        light: 'from-indigo-50 to-blue-50 border-indigo-200 hover:border-indigo-300', dark: 'from-indigo-900/40 to-blue-900/40 border-indigo-500/30 hover:border-indigo-400', iconLight: 'bg-indigo-100 text-indigo-600', iconDark: 'bg-indigo-400/20 text-indigo-400'
    },
    'dte-simples-fiscal': {
        label: 'Simples Fiscal',
        menu: 'dte-sub',
        description: 'Gestão simplificada de tributos e obrigações fiscais',
        href: 'https://simplesfiscal.prefeituramoderna.com.br/',
        icon: 'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
        light: 'from-emerald-50 to-green-50 border-emerald-200 hover:border-emerald-300', dark: 'from-emerald-900/40 to-green-900/40 border-emerald-500/30 hover:border-emerald-400', iconLight: 'bg-emerald-100 text-emerald-600', iconDark: 'bg-emerald-500/20 text-emerald-400'
    },
    'dte-helpdesk': {
        label: 'HelpDesk Tickets',
        menu: 'dte-sub',
        description: 'Suporte técnico e abertura de chamados OTOBO',
        href: 'https://www.sistematerra.com.br/otobo/customer.pl',
        icon: 'M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 12.728l-3.536-3.536M12 3v4m0 10v4m9-9h-4M7 12H3m8 0a1 1 0 102 0 1 1 0 00-2-2 0z',
        light: 'from-cyan-50 to-sky-50 border-cyan-200 hover:border-cyan-300', dark: 'from-cyan-900/40 to-sky-900/40 border-cyan-500/30 hover:border-cyan-400', iconLight: 'bg-cyan-100 text-cyan-600', iconDark: 'bg-cyan-500/20 text-cyan-400'
    }
};

const DEFAULT_BANNERS = Object.keys(BANNER_STATIC).map((key, index) => ({
    id: key,
    key: key,
    label: BANNER_STATIC[key].label,
    enabled: true,
    orderIndex: index
}));

// ==================== LISTAS AUXILIARES DE SUB-BANNERS ====================
const DTE_SUB_BANNERS_KEYS = [
    'dte-portal', 'dte-meuiss', 'dte-nfe', 'dte-iptu', 'dte-meuiptu', 'dte-login', 'dte-simples-fiscal', 'dte-helpdesk'
];


// ==================== BIBLIOTECA: CATEGORIAS BENTO BOX ====================
const BIBLIOTECA_CATEGORIAS = [
    {
        id: 'legislacao',
        label: 'Legislação Municipal',
        description: 'Leis e decretos do município',
        icon: 'M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l-3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3',
        size: 'wide',
        colorLight: 'from-amber-50 to-orange-50 border-amber-400 hover:border-amber-500',
        colorDark: 'from-amber-900/40 to-orange-900/40 border-amber-500/30 hover:border-amber-400',
        iconLight: 'bg-amber-100 text-amber-700',
        iconDark: 'bg-amber-500/20 text-amber-400',
        links: [
            { id: 'ctm', label: 'CTM – Cód. Tributário Municipal', href: '#', description: 'Lei Complementar nº 001/2003', badge: 'Em breve' },
            { id: 'lc116', label: 'LC 116/2003 – ISS Nacional', href: '#', description: 'Lei Complementar Federal do ISS', badge: 'Em breve' },
            { id: 'decreto', label: 'Decreto Regulamentador', href: '#', description: 'Regulamenta o CTM vigente', badge: 'Em breve' },
        ]
    },
    {
        id: 'manuais',
        label: 'Manuais e Procedimentos',
        description: 'Guias operacionais e procedimentos internos',
        icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01',
        size: 'normal',
        colorLight: 'from-orange-50 to-red-50 border-orange-400 hover:border-orange-500',
        colorDark: 'from-orange-900/40 to-red-900/40 border-orange-500/30 hover:border-orange-400',
        iconLight: 'bg-orange-100 text-orange-700',
        iconDark: 'bg-orange-500/20 text-orange-400',
        links: [
            { id: 'simples', label: 'Simples Nacional', href: '#', description: 'Manual do regime Simples Nacional', badge: 'PDF' },
            { id: 'dte-manual', label: 'Manual DTE', href: '#', description: 'Domicílio Tributário Eletrônico', badge: 'PDF' },
            { id: 'nfse-manual', label: 'Manual NFS-e', href: '#', description: 'Emissão de Nota Fiscal de Serviços', badge: 'Novo' },
        ]
    },
    {
        id: 'ebooks',
        label: 'E-books e Guias',
        description: 'Material de apoio e capacitação',
        icon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
        size: 'normal',
        colorLight: 'from-yellow-50 to-amber-50 border-yellow-400 hover:border-yellow-500',
        colorDark: 'from-yellow-900/40 to-amber-900/40 border-yellow-500/30 hover:border-yellow-400',
        iconLight: 'bg-yellow-100 text-yellow-700',
        iconDark: 'bg-yellow-500/20 text-yellow-400',
        links: [
            { id: 'ebook-iss', label: 'E-book ISS Explicado', href: '#', description: 'Guia completo sobre ISS municipal', badge: 'PDF' },
            { id: 'ebook-cnae', label: 'Guia CNAE Prático', href: '#', description: 'Como classificar atividades econômicas', badge: 'Em breve' },
        ]
    },
    {
        id: 'normas',
        label: 'Normas e Instruções',
        description: 'Resoluções, portarias e instruções normativas',
        icon: 'M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z',
        size: 'normal',
        colorLight: 'from-stone-50 to-amber-50 border-stone-400 hover:border-stone-500',
        colorDark: 'from-stone-900/40 to-amber-900/40 border-stone-500/30 hover:border-stone-400',
        iconLight: 'bg-stone-100 text-stone-700',
        iconDark: 'bg-stone-500/20 text-stone-400',
        links: [
            { id: 'instrucao-01', label: 'Instrução Normativa 01/2024', href: '#', description: 'Procedimentos de fiscalização', badge: 'Em breve' },
            { id: 'portaria-02', label: 'Portaria 02/2024', href: '#', description: 'Atualização de alíquotas', badge: 'Atualizado' },
        ]
    },
];

// ==================== MODAL DE BANNERS POR USUÁRIO ====================
function AdminUserBannersModal({ userId, userName, darkMode, onClose }) {
    const [banners, setBanners] = useState([]);
    const [loading, setLoading] = useState(true);
    const [savingId, setSavingId] = useState(null);
    const [resetting, setResetting] = useState(false);
    const [toast, setToast] = useState(null);
    const dragItem = useRef();
    const dragOverItem = useRef();

    useEffect(() => {
        loadUserBanners();
    }, [userId]);

    const loadUserBanners = async () => {
        setLoading(true);
        try {
            const data = await ApiService.adminGetUserBanners(userId);

            const allKeys = Object.keys(BANNER_STATIC);
            const merged = data.filter(b => BANNER_STATIC[b.key]);

            allKeys.forEach(key => {
                if (!merged.find(b => b.key === key)) {
                    const mapped = BANNER_STATIC[key];
                    if (['home', 'dte-sub', 'outros'].includes(mapped.menu)) {
                        merged.push({
                            id: key,
                            key: key,
                            label: mapped.label,
                            enabled: !mapped.adminOnly,
                            hasOverride: false
                        });
                    }
                }
            });

            const menuOrder = { 'home': 1, 'outros': 2, 'dte-sub': 3 };
            setBanners(merged.sort((a, b) => {
                const ma = BANNER_STATIC[a.key]?.menu || 'home';
                const mb = BANNER_STATIC[b.key]?.menu || 'home';
                if (ma !== mb) return menuOrder[ma] - menuOrder[mb];
                return (a.orderIndex ?? 99) - (b.orderIndex ?? 99);
            }));
        } catch (e) {
            setToast({ type: 'error', msg: 'Erro ao carregar banners do usuário.' });
        } finally {
            setLoading(false);
        }
    };

    const handleToggle = async (banner) => {
        setSavingId(banner.id);
        const newEnabled = !banner.enabled;
        // Optimistic UI update: atualiza a tela instantaneamente
        setBanners(prev => prev.map(b => b.id === banner.id ? { ...b, enabled: newEnabled, hasOverride: true } : b));

        try {
            await ApiService.adminToggleUserBanner(userId, banner.id, newEnabled);
            showToast('success', `"${BANNER_STATIC[banner.key]?.label || banner.label}" ${newEnabled ? 'ativado' : 'desativado'} para ${userName}.`);
        } catch (e) {
            // Reverte o estado em caso de falha da API
            setBanners(prev => prev.map(b => b.id === banner.id ? { ...b, enabled: banner.enabled, hasOverride: true } : b));
            showToast('error', 'Erro ao atualizar banner.');
        } finally {
            setSavingId(null);
        }
    };

    const handleReset = async () => {
        if (!confirm(`Resetar todos os banners de "${userName}" para o padrão global?`)) return;
        setResetting(true);
        try {
            await ApiService.adminResetUserBanners(userId);
            showToast('success', `Banners de "${userName}" resetados para o padrão global.`);
            await loadUserBanners();
        } catch (e) {
            showToast('error', 'Erro ao resetar banners.');
        } finally {
            setResetting(false);
        }
    };

    const handleSort = async () => {
        if (dragItem.current !== null && dragOverItem.current !== null && dragItem.current !== dragOverItem.current) {
            const _banners = [...banners];
            const dragged = _banners.splice(dragItem.current, 1)[0];
            _banners.splice(dragOverItem.current, 0, dragged);
            const orderedPayload = _banners.map((b, i) => ({ id: b.id, orderIndex: i }));
            setBanners(_banners);
            try {
                await ApiService.adminReorderUserBanners(userId, orderedPayload);
                showToast('success', 'Ordem atualizada!');
            } catch (e) {
                showToast('error', 'Erro ao salvar a nova ordem.');
                loadUserBanners();
            }
        }
        dragItem.current = null;
        dragOverItem.current = null;
    };

    const showToast = (type, msg) => {
        setToast({ type, msg });
        setTimeout(() => setToast(null), 3500);
    };

    const hasAnyOverride = banners.some(b => b.hasOverride);

    useEffect(() => {
        const onKey = (e) => { if (e.key === 'Escape') onClose(); };
        document.addEventListener('keydown', onKey);
        return () => document.removeEventListener('keydown', onKey);
    }, [onClose]);

    const GRUPOS = { home: 'Início', outros: 'Serviços internos', 'dte-sub': 'Dentro de Prefeitura Moderna' };

    return ReactDOM.createPortal(
        <div className="pc-sheet-layer">
            <div className="pc-sheet-backdrop" onClick={onClose} />
            <div className="pc-sheet pc-sheet--narrow" role="dialog" aria-modal="true" aria-labelledby="banners-usuario-titulo" style={{ '--accent': 'var(--pc-brand)' }}>
                <div className="pc-sheet-head">
                    <span className="pc-tile"><PcIcon name="sliders" size={20} /></span>
                    <div className="pc-sheet-heading">
                        <h2 id="banners-usuario-titulo" className="pc-sheet-title">Banners de {userName}</h2>
                        <p className="pc-sheet-sub">{hasAnyOverride ? 'Configuração personalizada ativa' : 'Seguindo o padrão global'}</p>
                    </div>
                    <button type="button" className="pc-iconbtn pc-sheet-close" aria-label="Fechar" onClick={onClose} autoFocus>
                        <PcIcon name="close" size={18} />
                    </button>
                </div>

                {toast && (
                    <div className={`pc-alert ${toast.type === 'success' ? 'pc-alert--ok' : 'pc-alert--error'}`} role="status" style={{ margin: '0 1.125rem .75rem' }}>
                        <PcIcon name={toast.type === 'success' ? 'check' : 'alert'} size={18} />
                        <span>{toast.msg}</span>
                    </div>
                )}

                <div className="pc-sheet-scroll">
                    {loading ? (
                        <div className="pc-loading"><span className="pc-spin" aria-hidden="true" />Carregando banners…</div>
                    ) : (
                        banners.map((banner, index) => {
                            const s = BANNER_STATIC[banner.key];
                            if (!s) return null;
                            const isSaving = savingId === banner.id;
                            const prevS = index > 0 ? BANNER_STATIC[banners[index - 1].key] : null;
                            const isNewGroup = !prevS || s.menu !== prevS.menu;
                            const label = s.label || banner.label;
                            return (
                                <React.Fragment key={banner.id}>
                                    {isNewGroup && <p className="pc-eyebrow pc-sheet-group">{GRUPOS[s.menu] || 'Geral'}</p>}
                                    <div
                                        className={`pc-brow ${banner.enabled ? '' : 'is-off'}`}
                                        draggable
                                        onDragStart={() => dragItem.current = index}
                                        onDragEnter={() => dragOverItem.current = index}
                                        onDragEnd={handleSort}
                                        onDragOver={e => e.preventDefault()}
                                    >
                                        <span className="pc-brow-grip" title="Arraste para reordenar"><PcIcon name="grip" size={16} /></span>
                                        <span className={`pc-tile ${s.imageIcon ? 'pc-tile--img' : ''}`} style={{ '--accent': mosaicAccent(s.accent, darkMode) }}>
                                            {s.imageIcon ? <img src={s.imageIcon} alt="" /> : (
                                                <svg width={18} height={18} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d={s.icon || 'M4 5h16'} />
                                                </svg>
                                            )}
                                        </span>
                                        <div className="pc-row-main">
                                            <span className="pc-row-name">{label}</span>
                                            <span className="pc-row-sub">{banner.enabled ? 'Visível' : 'Oculto'}</span>
                                        </div>
                                        <button
                                            type="button"
                                            role="switch"
                                            aria-checked={!!banner.enabled}
                                            aria-label={`${banner.enabled ? 'Ocultar' : 'Mostrar'} ${label}`}
                                            className={`pc-switch ${banner.enabled ? 'is-on' : ''} ${isSaving ? 'is-busy' : ''}`}
                                            onClick={() => handleToggle(banner)}
                                            disabled={isSaving}
                                        />
                                    </div>
                                </React.Fragment>
                            );
                        })
                    )}
                </div>

                <div className="pc-sheet-foot">
                    <span>Arraste para reordenar</span>
                    <button type="button" className="pc-btn pc-btn--sm" onClick={handleReset} disabled={!hasAnyOverride || resetting}>
                        <PcIcon name="rotate" size={15} />
                        {resetting ? 'Restaurando…' : 'Restaurar padrão'}
                    </button>
                </div>
            </div>
        </div>,
        document.body
    );
}



// ==================== PAINEL DE CONTROLE DE BANNERS ====================
function AdminBannersPanel({ darkMode }) {
    const [users, setUsers] = useState([]);
    const [loadingUsers, setLoadingUsers] = useState(true);
    const [toast, setToast] = useState(null);
    const [selectedUserModal, setSelectedUserModal] = useState(null); // {id, name}

    useEffect(() => {
        loadUsers();
    }, []);

    const loadUsers = async () => {
        setLoadingUsers(true);
        try {
            const data = await ApiService.getUsers();
            setUsers(data.filter(u => u.role !== 'admin' && (u.isAuthorized === true || u.isAuthorized === 1)));
        } catch (e) {
            showToast('error', 'Erro ao carregar usuários.');
        } finally {
            setLoadingUsers(false);
        }
    };

    const showToast = (type, msg) => {
        setToast({ type, msg });
        setTimeout(() => setToast(null), 3500);
    };

    const [filtro, setFiltro] = useState('');
    const termo = filtro.trim().toLowerCase();
    const visiveis = users.filter(u => !termo
        || (u.name || '').toLowerCase().includes(termo)
        || (u.username || '').toLowerCase().includes(termo));

    return (
        <div className="pc-page animate-fadeInUp">
            {selectedUserModal && (
                <AdminUserBannersModal
                    userId={selectedUserModal.id}
                    userName={selectedUserModal.name}
                    darkMode={darkMode}
                    onClose={() => setSelectedUserModal(null)}
                />
            )}

            <header className="pc-page-head">
                <div>
                    <h1 className="pc-page-title">Banners</h1>
                    <p className="pc-page-lead">Escolha quais módulos cada usuário vê na Início e em Serviços Internos. Sem personalização, vale o padrão global.</p>
                </div>
            </header>

            {toast && (
                <div className={`pc-alert ${toast.type === 'success' ? 'pc-alert--ok' : 'pc-alert--error'}`} role="status">
                    <PcIcon name={toast.type === 'success' ? 'check' : 'alert'} size={18} />
                    <span>{toast.msg}</span>
                </div>
            )}

            <section className="pc-box" aria-labelledby="banners-usuarios">
                <div className="pc-box-head">
                    <div>
                        <h2 id="banners-usuarios" className="pc-box-title">Personalização por usuário</h2>
                        <p className="pc-box-sub">{users.length} {users.length === 1 ? 'usuário autorizado' : 'usuários autorizados'}</p>
                    </div>
                    <div className="pc-input pc-input--sm pc-box-search">
                        <PcIcon name="search" size={16} />
                        <label htmlFor="banners-filtro" className="pc-sr-only">Filtrar usuários</label>
                        <input id="banners-filtro" type="search" value={filtro} onChange={(e) => setFiltro(e.target.value)} placeholder="Filtrar por nome ou usuário" />
                    </div>
                </div>

                {loadingUsers ? (
                    <div className="pc-loading"><span className="pc-spin" aria-hidden="true" />Carregando usuários…</div>
                ) : visiveis.length === 0 ? (
                    <div className="pc-empty">
                        <span className="pc-empty-ico"><PcIcon name="users" /></span>
                        <strong>{termo ? 'Nenhum usuário encontrado' : 'Nenhum usuário autorizado'}</strong>
                        <span>{termo ? `Nada corresponde a “${filtro}”.` : 'Usuários aparecem aqui depois de autorizados em Usuários.'}</span>
                    </div>
                ) : (
                    <ul className="pc-rows">
                        {visiveis.map(user => (
                            <li key={user.id} className="pc-row">
                                <span className="pc-avatar">{(user.name || user.username || '?').charAt(0).toUpperCase()}</span>
                                <div className="pc-row-main">
                                    <span className="pc-row-name">{user.name || user.username}</span>
                                    <span className="pc-row-sub pc-mono">@{user.username}</span>
                                </div>
                                <div className="pc-row-actions">
                                    <button type="button" className="pc-btn pc-btn--sm" onClick={() => setSelectedUserModal({ id: user.id, name: user.name || user.username })}>
                                        <PcIcon name="sliders" size={15} />
                                        Personalizar
                                    </button>
                                </div>
                            </li>
                        ))}
                    </ul>
                )}
            </section>
        </div>
    );
}
// ========================================================================

// ==================== CONSULTA ISS / CNAE ====================
// Resultados na própria página: filtro por alíquota, linha selecionável e
// painel de detalhe com o local de incidência (art. 3º da LC 116/2003).

const formatCnae = (valor) => {
    const digitos = String(valor ?? '').replace(/[^0-9]/g, '');
    if (digitos.length >= 7) {
        const d = digitos.padStart(7, '0');
        return `${d.slice(0, 4)}-${d.slice(4, 5)}/${d.slice(5, 7)}`;
    }
    return String(valor ?? '');
};

const aliquotaNum = (a) => parseFloat(String(a).replace(',', '.')) || 0;

const SEARCH_MODES = [
    { id: 'all', label: 'Tudo' },
    { id: 'text', label: 'Descrição' },
    { id: 'lc', label: 'Item LC' },
    { id: 'cnae', label: 'CNAE' }
];

const LIMITE_LINHAS = 300;

// ==================== GLOSSÁRIO DO SIMPLES NACIONAL ====================
// Explica os selos e classificações da consulta em linguagem simples, com a base legal.
// Textos conferidos na Res. CGSN nº 140/2018 vigente (arts. 8º, 15, 25 e 26).

const GLOSSARIO_SIMPLES = [
    {
        id: 'cnae',
        titulo: 'Situação do CNAE no Simples Nacional',
        fonte: 'Norma oficial em vigor: Resolução CGSN nº 140/2018, art. 8º e Anexos VI e VII.',
        onde: 'Aparece embaixo do código na tabela e no quadro do CNAE, no painel ao lado.',
        itens: [
            {
                id: 'impeditivo', selo: 'Impeditivo SN', classe: 'pc-badge pc-badge--crit',
                significa: 'A atividade deste CNAE impede a empresa de optar pelo Simples Nacional. O código está na lista de CNAEs impeditivos (Anexo VI).',
                pratica: 'Empresa com este CNAE no CNPJ não pode ser optante do Simples. Se ela aparecer como optante, há indício de enquadramento indevido, a ser verificado. Fora do Simples, o ISS segue a alíquota municipal mostrada nesta consulta.',
                base: 'Res. CGSN nº 140/2018, art. 8º, § 1º, e Anexo VI.'
            },
            {
                id: 'ambiguo', selo: 'Ambíguo SN', classe: 'pc-badge pc-badge--warn',
                significa: 'O mesmo código CNAE abrange atividades que impedem e atividades que permitem o Simples. O código, sozinho, não resolve: depende do que a empresa realmente faz.',
                pratica: 'A empresa pode optar desde que exerça apenas a parte permitida e declare expressamente que não se enquadra nas vedações. Confira a atividade efetivamente exercida: objeto social, notas emitidas e contratos.',
                base: 'Res. CGSN nº 140/2018, art. 8º, §§ 2º e 3º, e Anexo VII.'
            },
            {
                id: 'nao-impeditivo', selo: null,
                significa: 'O CNAE não está nem no Anexo VI nem no Anexo VII. A atividade, por si, não impede o Simples. Por isso a linha não tem selo.',
                pratica: 'A opção ainda pode ser vedada por outros motivos, como faturamento, composição societária ou débitos. Esta consulta não verifica esses pontos.',
                base: 'Res. CGSN nº 140/2018, art. 15 (demais vedações).'
            }
        ]
    },
    {
        id: 'subitem',
        titulo: 'Anexo de tributação do serviço (por subitem)',
        fonte: 'Referência preliminar: Anexo VIII da NFS-e (RFB), sem regra de negócio no emissor. As regras dos anexos estão nos arts. 25 e 26 da Res. CGSN nº 140/2018.',
        onde: 'Aparece na seção "Simples Nacional (PGDAS-D)" do painel e nas etiquetas das NBS. O número entre parênteses (7, 9, 13…) é o código de atividade do PGDAS-D usado pelo Anexo VIII.',
        itens: [
            {
                id: 'anexo-iii', selo: 'Anexo III', classe: 'pc-badge', estilo: { background: 'var(--pc-brand-soft)', color: 'var(--pc-brand)' },
                significa: 'Para a empresa do Simples, a receita deste serviço é tributada pela tabela do Anexo III.',
                pratica: 'Abrange, entre outros, ensino, agência de viagens e transporte municipal. É a tabela do anexo que define a alíquota cobrada no DAS.',
                base: 'Res. CGSN nº 140/2018, art. 25, § 1º, III.'
            },
            {
                id: 'anexo-iv', selo: 'Anexo IV', classe: 'pc-badge', estilo: { background: 'var(--pc-brand-soft)', color: 'var(--pc-brand)' },
                significa: 'A receita é tributada pela tabela do Anexo IV: construção de imóveis e obras de engenharia, vigilância, limpeza ou conservação, e serviços advocatícios.',
                pratica: 'Neste anexo, a contribuição previdenciária patronal (CPP) não está no DAS e é recolhida à parte.',
                base: 'Res. CGSN nº 140/2018, art. 25, § 1º, IV; LC nº 123/2006, art. 18, § 5º-C.'
            },
            {
                id: 'fator-r', selo: 'Anexo III ou V (Fator R)', classe: 'pc-badge', estilo: { background: 'var(--pc-brand-soft)', color: 'var(--pc-brand)' },
                significa: 'O anexo depende do fator "r": a folha de salários com encargos dos últimos 12 meses dividida pela receita bruta dos últimos 12 meses.',
                pratica: 'Fator "r" igual ou maior que 0,28 (28%): Anexo III. Menor que 0,28: Anexo V. Como depende da folha da empresa, pode mudar de um mês para outro.',
                base: 'Res. CGSN nº 140/2018, art. 25, § 1º, V, e art. 26.'
            },
            {
                id: 'impeditiva-subitem', selo: 'Impeditiva ao Simples', classe: 'pc-badge pc-badge--crit',
                significa: 'O Anexo VIII marca o serviço deste subitem como atividade que não pode ser exercida no Simples.',
                pratica: 'É uma referência preliminar. Para decidir, vale a situação do CNAE (Anexos VI e VII da Res. CGSN nº 140/2018), que é norma oficial.',
                base: 'Anexo VIII da NFS-e (RFB), coluna da atividade do Simples Nacional.'
            }
        ]
    }
];

// Classificação do Simples por subitem (código de atividade do Anexo VIII) → termo do glossário.
const termoGlossarioSn = (atividade) => {
    if (!atividade) return 'subitem';
    if (atividade.codigo === 'IMP') return 'impeditiva-subitem';
    if (/fator/i.test(atividade.rotulo)) return 'fator-r';
    if (/anexo iv/i.test(atividade.rotulo)) return 'anexo-iv';
    if (/anexo iii/i.test(atividade.rotulo)) return 'anexo-iii';
    return 'subitem';
};

function AjudaSimples({ foco, onClose }) {
    const sheetRef = useRef(null);
    const fecharRef = useRef(null);
    const tituloId = 'ajuda-simples-titulo';

    useEffect(() => {
        const anterior = document.activeElement;
        fecharRef.current?.focus();
        // Rola até o termo clicado (ou o grupo dele)
        const alvo = foco && sheetRef.current?.querySelector(`[data-termo="${foco}"]`);
        if (alvo) alvo.scrollIntoView({ block: 'start' });

        const onKey = (e) => {
            if (e.key === 'Escape') { e.preventDefault(); onClose(); return; }
            if (e.key === 'Tab' && sheetRef.current) {
                const focaveis = sheetRef.current.querySelectorAll('button, a[href], [tabindex="0"]');
                if (!focaveis.length) return;
                const primeiro = focaveis[0], ultimo = focaveis[focaveis.length - 1];
                if (e.shiftKey && document.activeElement === primeiro) { e.preventDefault(); ultimo.focus(); }
                else if (!e.shiftKey && document.activeElement === ultimo) { e.preventDefault(); primeiro.focus(); }
            }
        };
        document.addEventListener('keydown', onKey);
        return () => {
            document.removeEventListener('keydown', onKey);
            if (anterior && typeof anterior.focus === 'function') anterior.focus();
        };
    }, []);

    return ReactDOM.createPortal(
        <div className="pc-sheet-layer">
            <div className="pc-sheet-backdrop" onClick={onClose} />
            <div ref={sheetRef} className="pc-sheet" role="dialog" aria-modal="true" aria-labelledby={tituloId} style={{ '--accent': 'var(--pc-brand)' }}>
                <div className="pc-sheet-head">
                    <span className="pc-glossario-ico" aria-hidden="true"><PcIcon name="help" size={20} /></span>
                    <div className="pc-sheet-heading">
                        <h2 id={tituloId} className="pc-sheet-title">O que significam as situações do Simples Nacional</h2>
                        <p className="pc-sheet-sub">Os selos e classificações que a consulta mostra, em linguagem simples, com a base legal.</p>
                    </div>
                    <button ref={fecharRef} type="button" className="pc-iconbtn pc-sheet-close" aria-label="Fechar" onClick={onClose}>
                        <PcIcon name="close" size={18} />
                    </button>
                </div>
                <div className="pc-sheet-scroll custom-scrollbar">
                    {GLOSSARIO_SIMPLES.map(grupo => (
                        <section key={grupo.id} className="pc-glossario-grupo" data-termo={grupo.id} aria-labelledby={`glossario-${grupo.id}`}>
                            <h3 id={`glossario-${grupo.id}`}>{grupo.titulo}</h3>
                            <p className="pc-glossario-fonte">{grupo.fonte} {grupo.onde}</p>
                            {grupo.itens.map(item => (
                                <article key={item.id} data-termo={item.id} className={`pc-glossario-item${item.id === foco ? ' is-foco' : ''}`}>
                                    {item.selo
                                        ? <span className={item.classe} style={{ alignSelf: 'flex-start', ...(item.estilo || {}) }}>{item.selo}</span>
                                        : <strong className="pc-glossario-semselo">Sem selo (não impeditivo)</strong>}
                                    <p><strong>O que significa.</strong> {item.significa}</p>
                                    <p><strong>Na prática.</strong> {item.pratica}</p>
                                    <p className="pc-glossario-base">Base: {item.base}</p>
                                </article>
                            ))}
                        </section>
                    ))}
                    <section className="pc-glossario-grupo" data-termo="divergencia">
                        <h3>E quando as duas classificações não batem?</h3>
                        <div className="pc-glossario-nota">
                            <p>
                                <strong>Para saber se a empresa pode estar no Simples, vale a situação do CNAE.</strong> Ela é norma oficial.
                                O anexo por subitem só indica qual tabela de alíquotas se aplica ao serviço, para quem já é do Simples.
                            </p>
                            <p>
                                Exemplo: no subitem 15.01, o Anexo VIII indica "Fator R", mas os CNAEs de banco são impeditivos.
                                Um banco não pode ser do Simples, e o anexo por subitem nem chega a valer para ele.
                            </p>
                            <p>
                                Lembre também: em regra, a empresa do Simples paga o ISS dentro do DAS, pela tabela do anexo,
                                e não pela alíquota municipal desta consulta.
                            </p>
                        </div>
                    </section>
                </div>
            </div>
        </div>,
        document.body
    );
}

// Botão "O que significa?" que abre o glossário no termo indicado.
function BotaoAjuda({ termo, onAbrir, rotulo = 'O que significa?' }) {
    return (
        <button type="button" className="pc-ajuda-btn" onClick={() => onAbrir(termo)}>
            <PcIcon name="help" size={14} />
            {rotulo}
        </button>
    );
}

function ConsultaIssCnae({ data, listaNacional, searchTerm, setSearchTerm, mode, setMode, results, lastQuery, onSearch, recent, getIncidence }) {
    const [aliq, setAliq] = useState('all');
    const [selIndex, setSelIndex] = useState(0);
    const [ajuda, setAjuda] = useState(null); // termo do glossário do Simples aberto, ou null
    const [copiado, setCopiado] = useState(false);

    // Nova consulta: volta para "Todas" e seleciona a primeira linha.
    useEffect(() => { setAliq('all'); setSelIndex(0); }, [results]);

    const totalItens = useMemo(() => new Set((data || []).map(r => r['LIST LC'])).size, [data]);

    const linhas = useMemo(() => (results || []).map((r, i) => ({ ...r, __i: i })), [results]);
    const contagem = useMemo(() => {
        const acc = {};
        linhas.forEach(r => { acc[r['Alíquota']] = (acc[r['Alíquota']] || 0) + 1; });
        return Object.entries(acc).sort((a, b) => aliquotaNum(a[0]) - aliquotaNum(b[0]));
    }, [linhas]);

    const visiveis = aliq === 'all' ? linhas : linhas.filter(r => r['Alíquota'] === aliq);
    const atual = visiveis.find(r => r.__i === selIndex) || visiveis[0] || null;
    const irmaos = atual
        ? visiveis.filter(r => r['LIST LC'] === atual['LIST LC'] && r.__i !== atual.__i).slice(0, 6)
        : [];

    // Códigos de tributação nacional da NFS-e (Anexo B) do subitem selecionado.
    const desdobrosDe = (listLc) => window.BuscaFiscal.desdobramentos(listaNacional, listLc);
    const codigosNacionais = atual ? desdobrosDe(atual['LIST LC']) : [];
    const codigoBuscado = window.BuscaFiscal.codigoNacional(lastQuery);

    // NBS correlacionadas ao subitem (Anexo VIII, preliminar). As que casam com a NBS buscada vêm primeiro.
    const [nbsAberto, setNbsAberto] = useState(false);
    useEffect(() => { setNbsAberto(false); }, [atual?.['LIST LC']]);
    const nbsDe = (listLc) => window.BuscaFiscal.nbsDoSubitem(listaNacional, listLc);
    const nbsBuscada = window.BuscaFiscal.codigoNbs(lastQuery);
    const casaNbs = (n) => !!nbsBuscada && n.codigo.startsWith(nbsBuscada);
    const nbsDoAtual = atual ? [...nbsDe(atual['LIST LC'])].sort((a, b) => casaNbs(b) - casaNbs(a)) : [];
    const NBS_VISIVEIS = 6;

    // Atividade do Simples Nacional (PGDAS-D) do subitem (Anexo VIII, preliminar).
    const simplesDe = (listLc) => window.BuscaFiscal.simplesDoSubitem(listaNacional, listLc);
    const simplesDoAtual = atual ? simplesDe(atual['LIST LC']) : [];
    const rotuloSn = (cod) => listaNacional?.simplesNacional?.atividades?.[cod]?.rotulo || cod;

    // Situação do CNAE no Simples pela Res. CGSN nº 140/2018 (Anexos VI e VII, norma em vigor).
    const snCnae = (cnae) => window.BuscaFiscal.simplesDoCnae(listaNacional, cnae);
    const SN_CNAE = {
        impeditivo: { curto: 'Impeditivo SN', csv: 'Impeditivo (Anexo VI)', classe: 'pc-badge pc-badge--crit' },
        ambiguo: { curto: 'Ambíguo SN', csv: 'Ambíguo (Anexo VII)', classe: 'pc-badge pc-badge--warn' },
        'nao-impeditivo': { csv: 'Não impeditivo' }
    };
    const seloSnCnae = (cnae) => {
        const s = snCnae(cnae);
        const cfg = s && SN_CNAE[s.situacao];
        if (!cfg?.curto) return null;
        return (
            <span className={cfg.classe} style={{ height: '1.125rem', fontSize: '.625rem', padding: '0 .375rem', alignSelf: 'flex-start', fontFamily: 'var(--pc-font)' }}
                title={`Anexo ${s.anexo} da Res. CGSN nº 140/2018: ${s.denominacao}`}>
                {cfg.curto}
            </span>
        );
    };
    const nbsMostradas = nbsAberto ? nbsDoAtual : nbsDoAtual.slice(0, NBS_VISIVEIS);

    const submit = (e) => {
        e.preventDefault();
        onSearch(searchTerm, mode);
    };

    // Quantos resultados a última busca traria em cada pílula (só depois de buscar algo).
    const contagemModos = useMemo(() => {
        if (results === null || !lastQuery) return null;
        return Object.fromEntries(SEARCH_MODES.map(m =>
            [m.id, window.BuscaFiscal.filtrar(data, lastQuery, m.id, listaNacional).length]));
    }, [data, lastQuery, listaNacional, results]);

    const trocarModo = (novo) => {
        setMode(novo);
        if (results !== null) onSearch(searchTerm, novo);
    };

    const exportarCSV = () => {
        if (!visiveis.length) return;
        const cab = ['Item LC', 'Descrição do item (CTM)', 'CNAE', 'Descrição do CNAE', 'Alíquota', 'Local de incidência', 'Código de tributação nacional (NFS-e)',
            'NBS correlacionadas ao subitem (Anexo VIII, preliminar)', 'Simples Nacional (Anexo VIII, preliminar)',
            'Simples Nacional - CNAE (Res. CGSN 140/2018)'];
        const rows = visiveis.map(r => [r['LIST LC'], r[CAMPO_ITEM_LC], formatCnae(r['CNAE']), r['Descrição do CNAE'], r['Alíquota'], getIncidence(r['LIST LC']),
            desdobrosDe(r['LIST LC']).map(c => c.codigo).join(' | '),
            nbsDe(r['LIST LC']).map(n => n.codigo).join(' | '),
            simplesDe(r['LIST LC']).map(a => a.rotulo).join(' | '),
            SN_CNAE[snCnae(r['CNAE'])?.situacao]?.csv || '']);
        const csv = [cab, ...rows].map(l => l.map(v => '"' + String(v ?? '').replace(/"/g, '""') + '"').join(';')).join('\n');
        const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'consulta_iss_cnae_' + new Date().toISOString().split('T')[0] + '.csv';
        a.click();
        URL.revokeObjectURL(url);
    };

    const copiarCnae = async () => {
        if (!atual) return;
        try {
            await navigator.clipboard.writeText(formatCnae(atual['CNAE']));
            setCopiado(true);
            setTimeout(() => setCopiado(false), 1600);
        } catch (e) { /* área de transferência indisponível */ }
    };

    const alClass = (a) => {
        const n = Math.round(aliquotaNum(a));
        return `pc-al ${n >= 2 && n <= 4 ? 'pc-al--' + n : ''}`;
    };

    return (
        <div className="flex flex-col gap-6 animate-fadeInUp">
            <section className="pc-q">
                <div>
                    <h1 className="pc-q-title">Consulta ISS / CNAE</h1>
                    <p className="pc-q-lead">Cruze os itens da lista de serviços da LC nº 001/2003 (CTM) com os códigos CNAE e encontre a alíquota aplicável.</p>
                </div>

                <form className="pc-q-bar" role="search" onSubmit={submit}>
                    <label htmlFor="consulta-q" className="pc-sr-only">Pesquisar</label>
                    <div className="pc-input pc-q-input">
                        <PcIcon name="search" />
                        <input
                            id="consulta-q"
                            type="search"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            placeholder="Descrição, item LC (04.03), código nacional (07.02.01), NBS (1.0101.11.00) ou CNAE"
                            autoComplete="off"
                            autoFocus
                        />
                        <button type="submit" className="pc-btn pc-btn--primary" style={{ minHeight: '2.5rem' }}>Consultar</button>
                    </div>
                    <div className="pc-seg" role="group" aria-label="Pesquisar em">
                        {SEARCH_MODES.map(m => {
                            const n = contagemModos?.[m.id];
                            const rotulo = n == null ? m.label : `${m.label}: ${n} ${n === 1 ? 'resultado' : 'resultados'}`;
                            return (
                                <button key={m.id} type="button" aria-pressed={mode === m.id} onClick={() => trocarModo(m.id)}
                                    className={n === 0 ? 'is-vazio' : undefined} aria-label={rotulo} title={rotulo}>
                                    {m.label}
                                    {n != null && <span className="pc-seg-n" aria-hidden="true">{n}</span>}
                                </button>
                            );
                        })}
                    </div>
                </form>

                {recent.length > 0 && (
                    <div className="pc-recent">
                        <span style={{ color: 'var(--pc-muted)', marginRight: '.25rem' }}>Recentes</span>
                        {recent.map(q => (
                            <button key={q} type="button" className="pc-recent-btn" onClick={() => { setSearchTerm(q); onSearch(q, mode); }}>
                                <PcIcon name="history" size={14} />
                                {q}
                            </button>
                        ))}
                    </div>
                )}
            </section>

            {results === null ? (
                <section className="pc-detail" style={{ flex: 'none' }}>
                    <div className="pc-empty" style={{ padding: '2.5rem 1rem' }}>
                        <span className="pc-empty-ico"><PcIcon name="search" size={22} /></span>
                        <strong>Faça uma consulta</strong>
                        <span>Digite parte da descrição, o número do item da lista ou o código CNAE e pressione Enter.</span>
                    </div>
                </section>
            ) : (
                <>
                    <section className="pc-q-toolbar">
                        <p className="pc-q-count" role="status">
                            <strong>{visiveis.length}</strong> {visiveis.length === 1 ? 'resultado' : 'resultados'}
                            {lastQuery ? ` para “${lastQuery}”` : ' (base completa)'}
                        </p>
                        <div className="pc-q-filters">
                            {contagem.length > 1 && (
                                <>
                                    <span style={{ fontSize: '.8125rem', color: 'var(--pc-muted)' }}>Alíquota</span>
                                    <button type="button" className="pc-chip" aria-pressed={aliq === 'all'} onClick={() => setAliq('all')}>
                                        Todas <span className="pc-chip-n">{linhas.length}</span>
                                    </button>
                                    {contagem.map(([a, n]) => (
                                        <button key={a} type="button" className="pc-chip" aria-pressed={aliq === a} onClick={() => setAliq(a)}>
                                            {a} <span className="pc-chip-n">{n}</span>
                                        </button>
                                    ))}
                                </>
                            )}
                            {listaNacional?.cnaeSimples && (
                                <button type="button" className="pc-btn pc-btn--sm" onClick={() => setAjuda('cnae')}>
                                    <PcIcon name="help" size={16} />
                                    Legenda do Simples
                                </button>
                            )}
                            <button type="button" className="pc-btn pc-btn--sm" onClick={exportarCSV} disabled={!visiveis.length}>
                                <PcIcon name="download" size={16} />
                                Exportar CSV
                            </button>
                        </div>
                    </section>

                    <section className="pc-q-split">
                        <div className="pc-q-table">
                            <div className="pc-q-table-scroll custom-scrollbar">
                                <div className="pc-q-table-inner">
                                    <div className="pc-q-grid pc-q-head" aria-hidden="true">
                                        <span>Item LC</span><span>Serviço (CTM)</span><span>CNAE</span><span>Atividade CNAE</span><span style={{ textAlign: 'right' }}>Alíquota</span>
                                    </div>
                                    <div className="pc-q-rows custom-scrollbar">
                                        {visiveis.slice(0, LIMITE_LINHAS).map(r => (
                                            <button
                                                key={r.__i}
                                                type="button"
                                                className="pc-q-row pc-q-grid"
                                                aria-pressed={atual?.__i === r.__i}
                                                onClick={() => setSelIndex(r.__i)}
                                            >
                                                <span className="pc-q-code">{r['LIST LC']}</span>
                                                <span className="pc-q-txt pc-clip" title={r[CAMPO_ITEM_LC]}>{r[CAMPO_ITEM_LC]}</span>
                                                <span className="pc-q-cnae" style={{ display: 'flex', flexDirection: 'column', gap: '.1875rem' }}>
                                                    {formatCnae(r['CNAE'])}
                                                    {seloSnCnae(r['CNAE'])}
                                                </span>
                                                <span className="pc-q-txt pc-q-txt--ink pc-clip" title={r['Descrição do CNAE']}>{r['Descrição do CNAE']}</span>
                                                <span style={{ textAlign: 'right' }}><span className={alClass(r['Alíquota'])}>{r['Alíquota']}</span></span>
                                            </button>
                                        ))}
                                        {visiveis.length === 0 && (() => {
                                            // Código nacional que existe na NFS-e, mas cujo subitem não está na base municipal.
                                            const soNacional = codigoBuscado && (listaNacional?.codigos || []).find(c => c.codigo === codigoBuscado);
                                            return (
                                                <div className="pc-empty">
                                                    <span className="pc-empty-ico"><PcIcon name="search" size={22} /></span>
                                                    <strong>Nenhuma correspondência</strong>
                                                    {soNacional ? (
                                                        <span>
                                                            O código {soNacional.codigo} existe na lista nacional da NFS-e ({soNacional.descricao}),
                                                            mas o subitem {soNacional.subitem} não consta na Resolução SEFAZGO nº 01/2021, então não há CNAE nem alíquota municipal cadastrados.
                                                        </span>
                                                    ) : (
                                                        (() => {
                                                            // Pílula escolhida não combina com o tipo do termo: oferece a que tem resultado.
                                                            const melhor = contagemModos && SEARCH_MODES
                                                                .filter(m => m.id !== mode && contagemModos[m.id] > 0)
                                                                .sort((a, b) => contagemModos[b.id] - contagemModos[a.id])[0];
                                                            return melhor ? (
                                                                <>
                                                                    <span>Nada em “{SEARCH_MODES.find(m => m.id === mode)?.label}”, mas este termo tem resultados em outra pílula.</span>
                                                                    <button type="button" className="pc-btn pc-btn--sm" onClick={() => trocarModo(melhor.id)}>
                                                                        Ver {contagemModos[melhor.id]} em “{melhor.label}”
                                                                    </button>
                                                                </>
                                                            ) : (
                                                                <span>Tente um termo mais curto, o número do item da LC, o código nacional, a NBS ou o código CNAE.</span>
                                                            );
                                                        })()
                                                    )}
                                                </div>
                                            );
                                        })()}
                                    </div>
                                </div>
                            </div>
                            {visiveis.length > LIMITE_LINHAS && (
                                <p className="pc-q-foot">Mostrando {LIMITE_LINHAS} de {visiveis.length}. Refine a busca ou exporte o CSV para ver tudo.</p>
                            )}
                        </div>

                        <aside className="pc-detail" aria-label="Detalhe da correspondência">
                            {atual ? (
                                <>
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="flex flex-col gap-1">
                                            <span className="pc-eyebrow">Item da lista</span>
                                            <span className="pc-detail-lc">{atual['LIST LC']}</span>
                                        </div>
                                        <div className="flex flex-col items-end gap-1">
                                            <span className="pc-eyebrow">Alíquota ISS</span>
                                            <span className="pc-detail-al">{atual['Alíquota']}</span>
                                        </div>
                                    </div>
                                    <p style={{ margin: 0, fontSize: '.9375rem', lineHeight: 1.55, color: 'var(--pc-ink-2)' }}>{atual[CAMPO_ITEM_LC]}</p>
                                    <div className="pc-detail-box">
                                        <div className="flex items-center justify-between gap-3">
                                            <span className="pc-eyebrow">CNAE</span>
                                            <button type="button" className="pc-btn pc-btn--sm" style={{ minHeight: '2rem' }} onClick={copiarCnae}>
                                                <PcIcon name="copy" size={14} />
                                                {copiado ? 'Copiado' : 'Copiar'}
                                            </button>
                                        </div>
                                        <span className="pc-mono" style={{ fontSize: '1.125rem', fontWeight: 600 }}>{formatCnae(atual['CNAE'])}</span>
                                        <span style={{ fontSize: '.875rem', lineHeight: 1.5, color: 'var(--pc-ink-2)' }}>{atual['Descrição do CNAE']}</span>
                                        {(() => {
                                            const s = snCnae(atual['CNAE']);
                                            if (!s) return null;
                                            const nota = { fontSize: '.75rem', lineHeight: 1.45, color: 'var(--pc-ink-2)' };
                                            if (s.situacao === 'nao-impeditivo') {
                                                return (
                                                    <span style={{ ...nota, color: 'var(--pc-muted)' }}>
                                                        Simples Nacional: CNAE não consta nos Anexos VI e VII da Res. CGSN nº 140/2018 (não impeditivo pela CNAE; as demais vedações do art. 17 da LC 123/2006 continuam valendo).{' '}
                                                        <BotaoAjuda termo="nao-impeditivo" onAbrir={setAjuda} />
                                                    </span>
                                                );
                                            }
                                            return (
                                                <div className="flex flex-col gap-1" style={{ borderTop: '1px solid var(--pc-line)', paddingTop: '.5rem' }}>
                                                    <span className={SN_CNAE[s.situacao].classe} style={{ alignSelf: 'flex-start' }}>
                                                        {s.situacao === 'impeditivo' ? 'Impeditivo ao Simples Nacional' : 'Ambíguo no Simples Nacional'}
                                                    </span>
                                                    <span style={nota}>
                                                        {s.situacao === 'impeditivo'
                                                            ? `Consta no Anexo VI da Res. CGSN nº 140/2018 (CNAEs impeditivos): "${s.denominacao}".`
                                                            : `Consta no Anexo VII da Res. CGSN nº 140/2018: o código abrange atividade impeditiva e permitida ("${s.denominacao}"). A opção depende da atividade efetivamente exercida.`}
                                                    </span>
                                                    <BotaoAjuda termo={s.situacao} onAbrir={setAjuda} />
                                                </div>
                                            );
                                        })()}
                                    </div>
                                    <div className="flex flex-col gap-1">
                                        <span className="pc-eyebrow">Local de incidência (art. 3º LC 116)</span>
                                        <span style={{ fontSize: '.875rem', fontWeight: 500 }}>{getIncidence(atual['LIST LC'])}</span>
                                    </div>
                                    <div className="flex flex-col gap-2">
                                        <span className="pc-eyebrow">Código de tributação nacional (NFS-e)</span>
                                        {codigosNacionais.length > 1 && (
                                            <span style={{ fontSize: '.8125rem', lineHeight: 1.45, color: 'var(--pc-muted)' }}>
                                                Na NFS-e Nacional este subitem tem {codigosNacionais.length} desdobramentos. Use o que corresponde ao serviço; a alíquota e os CNAEs são os do subitem {atual['LIST LC']}.
                                            </span>
                                        )}
                                        {codigosNacionais.length ? codigosNacionais.map(c => {
                                            const destaque = c.codigo === codigoBuscado;
                                            return (
                                                <div key={c.codigo} className="pc-detail-box" style={{ gap: '.25rem', padding: '.625rem .75rem', ...(destaque ? { borderColor: 'var(--pc-brand)' } : {}) }}>
                                                    <span className="pc-mono" style={{ fontSize: '.875rem', fontWeight: 600, color: 'var(--pc-brand)' }}>
                                                        {c.codigo}{destaque ? ' · buscado' : ''}
                                                    </span>
                                                    <span style={{ fontSize: '.8125rem', lineHeight: 1.5, color: 'var(--pc-ink-2)' }}>{c.descricao}</span>
                                                </div>
                                            );
                                        }) : (
                                            <span style={{ fontSize: '.8125rem', color: 'var(--pc-muted)' }}>
                                                {listaNacional ? 'Subitem sem código na lista nacional.' : 'Lista nacional não carregada.'}
                                            </span>
                                        )}
                                    </div>
                                    {listaNacional?.simplesNacional && (
                                        <div className="flex flex-col gap-2">
                                            <div className="flex items-center justify-between gap-2">
                                                <span className="pc-eyebrow">Simples Nacional (PGDAS-D)</span>
                                                <BotaoAjuda termo={termoGlossarioSn(simplesDoAtual[0])} onAbrir={setAjuda} />
                                            </div>
                                            {simplesDoAtual.length ? (
                                                <>
                                                    {simplesDoAtual.map(a => (
                                                        <div key={a.codigo} className="pc-detail-box" style={{ gap: '.25rem', padding: '.625rem .75rem' }}>
                                                            <span style={{ fontSize: '.875rem', fontWeight: 600, color: a.codigo === 'IMP' ? 'var(--pc-danger)' : 'var(--pc-ink)' }}>
                                                                {a.rotulo}
                                                            </span>
                                                            <span style={{ fontSize: '.75rem', lineHeight: 1.45, color: 'var(--pc-ink-2)' }}>
                                                                {a.descricao} <span className="pc-mono" style={{ color: 'var(--pc-muted)' }}>(atividade {a.codigo})</span>
                                                            </span>
                                                        </div>
                                                    ))}
                                                    {simplesDoAtual.length > 1 && (
                                                        <span style={{ fontSize: '.75rem', lineHeight: 1.45, color: 'var(--pc-ink-2)' }}>
                                                            Depende do serviço. Quando o Anexo VIII liga a classificação a uma NBS, ela aparece ao lado da NBS, abaixo.
                                                        </span>
                                                    )}
                                                </>
                                            ) : (
                                                <span style={{ fontSize: '.8125rem', color: 'var(--pc-muted)' }}>Subitem sem classificação no Anexo VIII.</span>
                                            )}
                                            <span style={{ fontSize: '.75rem', lineHeight: 1.45, color: 'var(--pc-muted)' }} title={listaNacional.simplesNacional.aviso}>
                                                Correlação preliminar do Anexo VIII (RFB). Confirme o enquadramento na LC 123/2006 e na Resolução CGSN nº 140/2018.
                                            </span>
                                        </div>
                                    )}
                                    {listaNacional?.nbs && (
                                        <div className="flex flex-col gap-2">
                                            <span className="pc-eyebrow">NBS correlacionadas ao subitem {atual['LIST LC']}</span>
                                            <span style={{ fontSize: '.75rem', lineHeight: 1.45, color: 'var(--pc-muted)' }} title={listaNacional.nbs.aviso}>
                                                Correlação preliminar do Anexo VIII (RFB), sem regra de negócio no emissor da NFS-e. Vale para todos os desdobramentos do subitem.
                                            </span>
                                            {nbsDoAtual.length ? (
                                                <>
                                                    {nbsMostradas.map(n => (
                                                        <div key={n.codigo} className="flex items-baseline gap-2" style={casaNbs(n) ? { background: 'var(--pc-brand-soft)', borderRadius: '.375rem', padding: '.125rem .375rem', margin: '0 -.375rem' } : undefined}>
                                                            <span className="pc-mono" style={{ fontSize: '.8125rem', color: 'var(--pc-brand)', flex: 'none' }}>{n.codigo}</span>
                                                            <span style={{ fontSize: '.8125rem', lineHeight: 1.45, color: 'var(--pc-ink-2)' }}>
                                                                {n.descricao}
                                                                {simplesDoAtual.length > 1 && n.sn && (
                                                                    <span className={`pc-badge${n.sn === 'IMP' ? ' pc-badge--crit' : ''}`} style={{ marginLeft: '.375rem', height: '1.25rem', fontSize: '.6875rem', verticalAlign: 'middle', ...(n.sn === 'IMP' ? {} : { background: 'var(--pc-brand-soft)', color: 'var(--pc-brand)' }) }}>{rotuloSn(n.sn)}</span>
                                                                )}
                                                            </span>
                                                        </div>
                                                    ))}
                                                    {nbsDoAtual.length > NBS_VISIVEIS && (
                                                        <button type="button" className="pc-btn pc-btn--sm" style={{ alignSelf: 'flex-start', minHeight: '2rem' }} onClick={() => setNbsAberto(v => !v)} aria-expanded={nbsAberto}>
                                                            {nbsAberto ? 'Mostrar menos' : `Mostrar todas (${nbsDoAtual.length})`}
                                                        </button>
                                                    )}
                                                </>
                                            ) : (
                                                <span style={{ fontSize: '.8125rem', color: 'var(--pc-muted)' }}>Nenhuma NBS correlacionada a este subitem no Anexo VIII.</span>
                                            )}
                                        </div>
                                    )}
                                    <div className="flex flex-col gap-2">
                                        <h2 style={{ margin: 0, fontSize: '.875rem', fontWeight: 600 }}>Outros CNAEs do item {atual['LIST LC']} nesta busca</h2>
                                        {irmaos.length ? irmaos.map(r => (
                                            <button key={r.__i} type="button" className="pc-detail-sib" onClick={() => setSelIndex(r.__i)}>
                                                <span className="pc-mono" style={{ fontSize: '.8125rem', color: 'var(--pc-brand)', flex: 'none' }}>{formatCnae(r['CNAE'])}</span>
                                                <span className="pc-clip" style={{ fontSize: '.8125rem', color: 'var(--pc-ink-2)' }}>{r['Descrição do CNAE']}</span>
                                            </button>
                                        )) : (
                                            <span style={{ fontSize: '.8125rem', color: 'var(--pc-muted)' }}>Nenhum outro CNAE deste item nos resultados.</span>
                                        )}
                                    </div>
                                </>
                            ) : (
                                <span style={{ fontSize: '.875rem', color: 'var(--pc-muted)' }}>Selecione um resultado para ver os detalhes.</span>
                            )}
                        </aside>
                    </section>
                </>
            )}

            {ajuda && <AjudaSimples foco={ajuda} onClose={() => setAjuda(null)} />}

            <footer className="pc-q-note">
                <span>Base: Lei Complementar nº 001/2003 — Código Tributário Municipal</span>
                <span><span className="pc-mono">{totalItens}</span> itens · <span className="pc-mono">{(data || []).length.toLocaleString('pt-BR')}</span> correspondências CNAE</span>
            </footer>
        </div>
    );
}

function App() {
    // Estados de autenticação
    const [isAuthenticated, setIsAuthenticated] = useState(() => {
        return localStorage.getItem('isAuthenticated') === 'true';
    });
    const [currentUser, setCurrentUser] = useState(() => {
        const savedUser = localStorage.getItem('currentUser');
        return savedUser ? JSON.parse(savedUser) : null;
    });

    const [isSessionValidating, setIsSessionValidating] = useState(true);

    useEffect(() => {
        const validate = async () => {
            if (isAuthenticated) {
                try {
                    const validUser = await ApiService.validateSession();
                    if (validUser) {
                        setCurrentUser(validUser);
                    } else {
                        setIsAuthenticated(false);
                        setCurrentUser(null);
                    }
                } catch (error) {
                    // Se o erro for de servidor dormindo (Railway), iniciamos o despertar
                    if (error.message.includes('fetch') || error.message.includes('despertando') || error.message.includes('sleeping')) {
                        console.log('Servidor dormindo detectado na validação. Iniciando despertar...');
                        setWakeProgress(1);

                        let retryCount = 0;
                        const maxRetries = 30;
                        const retryValidate = async () => {
                            retryCount++;
                            setWakeProgress(Math.min(95, Math.floor((retryCount / maxRetries) * 100)));

                            try {
                                const validUser = await ApiService.validateSession();
                                setWakeProgress(100);
                                setTimeout(() => {
                                    if (validUser) setCurrentUser(validUser);
                                    setWakeProgress(0);
                                    setIsSessionValidating(false);
                                }, 600);
                            } catch (retryError) {
                                if (retryCount < maxRetries) {
                                    setTimeout(retryValidate, 1000);
                                } else {
                                    setWakeProgress(0);
                                    setIsSessionValidating(false);
                                    setIsAuthenticated(false); // Desiste e manda pro login
                                }
                            }
                        };
                        setTimeout(retryValidate, 1000);
                        return; // O setIsSessionValidating(false) será chamado no final do retry
                    } else {
                        setIsAuthenticated(false);
                        setCurrentUser(null);
                    }
                }
            }
            setIsSessionValidating(false);
        };
        validate();
    }, [isAuthenticated]);

    // Estado de navegação - Views: 'home' | 'search' | 'profile' | 'admin-dashboard' | 'admin-users'
    const [currentView, setCurrentView] = useState('home');
    // Sidebar mobile: abre/fecha no celular
    const [sidebarMobileOpen, setSidebarMobileOpen] = useState(false);

    const [data, setData] = useState([]);
    // Lista de Serviços Nacional da NFS-e (Anexo B), gerada por tools/importar_lista_nacional.py.
    const [listaNacional, setListaNacional] = useState(null);
    const [filteredData, setFilteredData] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [searchMode, setSearchMode] = useState('all'); // all | text | lc | cnae
    const [searchResults, setSearchResults] = useState(null); // null = nenhuma consulta feita ainda
    const [lastQuery, setLastQuery] = useState('');
    const [darkMode, setDarkMode] = useState(() => {
        const saved = localStorage.getItem('darkMode');
        return saved ? JSON.parse(saved) : false;
    });
    // Últimas 5 consultas, guardadas por usuário neste navegador.
    const recentKey = 'consultaRecentes:' + (currentUser?.username || 'anon');
    const [recentSearches, setRecentSearches] = useState([]);
    useEffect(() => {
        try {
            const saved = JSON.parse(localStorage.getItem(recentKey) || '[]');
            setRecentSearches(Array.isArray(saved) ? saved.slice(0, 5) : []);
        } catch (e) {
            setRecentSearches([]);
        }
    }, [recentKey]);



    // Estado da Tela de Bloqueio por inatividade
    const [isLockedOut, setIsLockedOut] = useState(() => {
        return localStorage.getItem('isLockedOut') === 'true';
    });
    const [unlockPassword, setUnlockPassword] = useState('');
    const [unlockError, setUnlockError] = useState('');
    const [isUnlocking, setIsUnlocking] = useState(false);
    const [wakeProgress, setWakeProgress] = useState(0); // 0 a 100
    const inactivityTimeoutRef = useRef(null);
    const [lockscreenTimeout, setLockscreenTimeout] = useState('5');
    const [tempTimeoutVal, setTempTimeoutVal] = useState('5');
    const [isSavingTimeout, setIsSavingTimeout] = useState(false);

    // Estado para usuários pendentes (apenas admin)
    const [pendingUsers, setPendingUsers] = useState([]);
    // Força re-render da lista de usuários na view admin após bloqueio/delete/reset
    const [adminUsersListKey, setAdminUsersListKey] = useState(0);
    const [auditUserFilter, setAuditUserFilter] = useState('');
    const [auditTypeFilter, setAuditTypeFilter] = useState(''); // 'banner', 'login_failure', etc.
    const [auditRange, setAuditRange] = useState('7d'); // janela temporal da Central de Auditoria
    const [bibliotecaModalOpen, setBibliotecaModalOpen] = useState(false);
    const [bibliotecaCategoria, setBibliotecaCategoria] = useState(null);
    const [bibliotecaSearch, setBibliotecaSearch] = useState('');
    const [openGroup, setOpenGroup] = useState(null); // card de grupo aberto como folha na Início

    const handleSortBanners = async () => {
        if (!currentUser || currentUser.role !== 'admin') return;

        if (dragItem.current !== null && dragOverItem.current !== null && dragItem.current !== dragOverItem.current) {
            setIsReorderingBanners(true);
            const _banners = [...bannerConfig];

            // Adjust dragged array locally
            const draggedItemContent = _banners.splice(dragItem.current, 1)[0];
            _banners.splice(dragOverItem.current, 0, draggedItemContent);

            const orderedPayload = _banners.map((b, index) => ({ id: b.id, orderIndex: index }));

            setBannerConfig(_banners);

            try {
                await ApiService.reorderBanners(orderedPayload);
            } catch (e) {
                console.error("Falha ao salvar a reordenação.", e);
            } finally {
                setIsReorderingBanners(false);
            }
        }

        // Reset refs
        dragItem.current = null;
        dragOverItem.current = null;
    };

    // Estado de configuração de banners
    const [bannerConfig, setBannerConfig] = useState(DEFAULT_BANNERS);

    // Drag and Drop Banners refs
    const dragItem = useRef();
    const dragOverItem = useRef();
    const [isReorderingBanners, setIsReorderingBanners] = useState(false);
    const [isDraggingBanners, setIsDraggingBanners] = useState(false); // New state for global CSS
    const [dragOverBannerId, setDragOverBannerId] = useState(null); // Card sob o cursor durante o arraste
    const dragSection = useRef(null); // Seção do card arrastado: só aceita soltar dentro dela

    const [freezeModalBanner, setFreezeModalBanner] = useState(null);

    // Carregar/recarregar config de banners ao montar e sempre que voltar para Home
    useEffect(() => {
        const loadBanners = () => {
            // Passa o token para receber banners personalizados do usuário
            ApiService.getBanners()
                .then(data => {
                    // Mescla banners da API com os defaults para garantir que novos banners apareçam
                    // mesmo se o backend estiver desatualizado (sem restart)
                    const merged = data.filter(b => BANNER_STATIC[b.key]);
                    DEFAULT_BANNERS.forEach(def => {
                        if (!merged.find(b => b.key === def.key)) {
                            merged.push(def);
                        }
                    });
                    setBannerConfig(merged);
                })
                .catch(() => {
                    setBannerConfig(DEFAULT_BANNERS);
                });
        };
        loadBanners();
    }, [currentView, isAuthenticated]);

    // Função para recarregar banners manualmente (ex: após gerenciar banners de um usuário)
    const reloadBanners = () => {
        ApiService.getBanners()
            .then(data => {
                const merged = data.filter(b => BANNER_STATIC[b.key]);
                DEFAULT_BANNERS.forEach(def => {
                    if (!merged.find(b => b.key === def.key)) {
                        merged.push(def);
                    }
                });
                setBannerConfig(merged);
            })
            .catch(() => { });
    };

    useEffect(() => {
        if (currentUser?.role === 'admin') {
            loadPendingUsers();
        }
    }, [currentUser]);

    const loadPendingUsers = async () => {
        try {
            const users = await ApiService.getUsers();
            // SQLite boolean returns 1 or 0 for isAuthorized, or false/true
            const pending = users.filter(u => u.isAuthorized === false || u.isAuthorized === 0);
            setPendingUsers(pending);
        } catch (error) {
            console.error("Erro ao carregar usuários pendentes:", error);
        }
    };

    const handleAuthorizeUser = async (userId) => {
        if (confirm('Deseja autorizar este usuário?')) {
            try {
                await ApiService.authorizeUser(userId);
                loadPendingUsers();
                setAdminUsersListKey(k => k + 1); // Recarrega a tabela de admin também
            } catch (error) {
                alert('Erro ao autorizar usuário: ' + error.message);
            }
        }
    };

    const handleFreezeToggleGlobal = async (banner, reason = 'maintenance') => {
        if (!currentUser || currentUser.role !== 'admin') return;

        const newFrozen = !banner.isFrozen;
        // Se estiver descongelando, o motivo não importa (será limpo ou ignorado)
        // Se estiver congelando, usa o reason passado
        const finalReason = newFrozen ? reason : 'maintenance';

        // Atualização Otimista da UI
        setBannerConfig(prev => prev.map(b => b.id === banner.id ? { ...b, isFrozen: newFrozen, freezeReason: finalReason } : b));

        try {
            // Passa o motivo para a API (precisa atualizar ApiService.adminFreezeBanner para aceitar 2 args)
            await ApiService.adminFreezeBanner(banner.id, newFrozen, finalReason);
            // Sincroniza dashboard se estiver aberto
            loadAuditData();
        } catch (e) {
            console.error("Erro ao congelar banner:", e);
            // Reverte em caso de erro
            setBannerConfig(prev => prev.map(b => b.id === banner.id ? { ...b, isFrozen: banner.isFrozen, freezeReason: banner.freezeReason } : b));
        }
    };

    // Estados para estatísticas de uso backend
    const [statistics, setStatistics] = useState({
        totalAccesses: 0,
        totalBannerClicks: 0,
        totalRegisteredUsers: 0, // Novo
        lastAccess: null,
        dailyAccesses: {},
        searchHistory: [],
        userSessions: {},
        bannerClicks: {}
    });

    const [isAuditLoading, setIsAuditLoading] = useState(false);

    // Carregar dados reais da API quando estiver na view admin-dashboard
    useEffect(() => {
        if (currentView === 'admin-dashboard' && currentUser?.role === 'admin') {
            loadAuditData();
        }
    }, [currentView, currentUser]);

    const loadAuditData = async () => {
        setIsAuditLoading(true);
        try {
            const data = await ApiService.getAuditStats();
            setStatistics({
                totalAccesses: data.totalAccesses,
                totalBannerClicks: data.totalBannerClicks,
                totalRegisteredUsers: data.totalRegisteredUsers || 0,
                lastAccess: null,
                dailyAccesses: { [new Date().toDateString()]: data.sessionsToday },
                searchHistory: data.searchHistory,
                userSessions: { 'Usuários Únicos': data.uniqueUsers },
                bannerClicks: data.bannerClicks
            });
        } catch (e) {
            console.error('Erro ao buscar auditoria do backend:', e);
            // Fallback não exibe erro invasivo, apenas mantém zeros
        } finally {
            setIsAuditLoading(false);
        }
    };

    // Funções para estatísticas seguras (Apenas compatibilidade para evitar quebras em logs locais)
    const updateStatistics = (type, data = {}) => {
        if (type === 'bannerClick') {
            ApiService.logEvent('banner_clicked', {
                bannerLabel: data.bannerLabel
            }).catch(e => console.error('Erro ao registrar clique:', e));
        }
    };
    // Funções de autenticação
    const handleLogin = (user) => {
        setIsAuthenticated(true);
        setCurrentUser(user);
        setIsLockedOut(false); // Reseta o bloqueio fantasma
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('currentUser', JSON.stringify(user));
        localStorage.setItem('isLockedOut', 'false'); // Limpa do armazenamento

        // Registrar acesso nas estatísticas
        updateStatistics('access', {
            username: user.username,
            role: user.role
        });
    };

    const handleLogout = () => {
        setIsAuthenticated(false);
        setCurrentUser(null);
        setCurrentView('home');
        setIsLockedOut(false);
        localStorage.removeItem('isAuthenticated');
        localStorage.removeItem('currentUser');
        localStorage.removeItem('isLockedOut');
    };

    const handleCredentialsChanged = (updatedUser) => {
        setCurrentUser(updatedUser);
        localStorage.setItem('currentUser', JSON.stringify(updatedUser));

        // Registrar alteração de credenciais nas estatísticas
        updateStatistics('credentialChange', {
            username: updatedUser.username,
            role: updatedUser.role
        });
    };

    // ----- LOGICA DE INATIVIDADE DINAMICA -----
    const resetInactivityTimer = () => {
        if (!isAuthenticated || isLockedOut) return;

        if (inactivityTimeoutRef.current) {
            clearTimeout(inactivityTimeoutRef.current);
        }

        if (lockscreenTimeout === 'free') {
            return;
        }

        const minutes = parseInt(lockscreenTimeout, 10);
        if (isNaN(minutes) || minutes <= 0) return;

        const timeoutMs = minutes * 60 * 1000;

        inactivityTimeoutRef.current = setTimeout(() => {
            setIsLockedOut(true);
            localStorage.setItem('isLockedOut', 'true');
        }, timeoutMs);
    };

    useEffect(() => {
        localStorage.setItem('isLockedOut', isLockedOut);
    }, [isLockedOut]);

    useEffect(() => {
        if (isAuthenticated && !isLockedOut) {
            // Inicia o timer na montagem do effect
            resetInactivityTimer();

            // Adiciona listeners para resetar o timer ao interagir
            const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
            events.forEach(event => window.addEventListener(event, resetInactivityTimer));

            return () => {
                if (inactivityTimeoutRef.current) clearTimeout(inactivityTimeoutRef.current);
                events.forEach(event => window.removeEventListener(event, resetInactivityTimer));
            };
        }
    }, [isAuthenticated, isLockedOut, lockscreenTimeout]);

    // Carregar configuração do lockscreen ao autenticar
    useEffect(() => {
        if (isAuthenticated) {
            ApiService.getLockscreenTimeout()
                .then(res => {
                    if (res && res.timeout) {
                        setLockscreenTimeout(res.timeout);
                        setTempTimeoutVal(res.timeout);
                    }
                })
                .catch(err => {
                    console.error("Erro ao carregar tempo de bloqueio:", err);
                });
        }
    }, [isAuthenticated]);

    const handleSaveTimeout = async (value) => {
        let finalVal = value;
        if (value === 'custom') {
            finalVal = '15'; // Valor padrão inicial
        }
        if (finalVal !== 'free' && (isNaN(parseInt(finalVal)) || parseInt(finalVal) <= 0)) {
            alert('Por favor, insira um valor válido em minutos.');
            return;
        }
        
        try {
            setIsSavingTimeout(true);
            await ApiService.updateLockscreenTimeout(finalVal);
            setLockscreenTimeout(finalVal);
            setTempTimeoutVal(finalVal);
            alert('Configuração de tempo de bloqueio atualizada com sucesso!');
        } catch (e) {
            alert('Erro ao salvar configuração: ' + e.message);
        } finally {
            setIsSavingTimeout(false);
        }
    };

    const handleUnlockSubmit = async (e) => {
        if (e) e.preventDefault();

        setUnlockError('');
        setIsUnlocking(true);

        try {
            // Tenta fazer login novamente com a mesma conta
            await ApiService.login(currentUser.username, unlockPassword);
            setIsLockedOut(false);
            localStorage.setItem('isLockedOut', 'false');
            setUnlockPassword('');
            setIsUnlocking(false);
        } catch (error) {
            // Se o erro vier do Soft Loading (TypeError fetch / 503), ele já lançou o evento global.
            // Acionamos um retry automático para re-submeter a senha validada quando o backend acordar.
            if (error.message.includes('fetch') || error.message.includes('despertando') || (error.message && error.message.includes('sleeping'))) {
                setUnlockError('');
                setWakeProgress(1); // Inicia progresso

                let retryCount = 0;
                const maxRetries = 30;
                const retryLogin = async () => {
                    retryCount++;
                    // Atualiza a barra reservando 100% para o sucesso
                    setWakeProgress(Math.min(95, Math.floor((retryCount / maxRetries) * 100)));

                    try {
                        await ApiService.login(currentUser.username, unlockPassword);
                        setWakeProgress(100);
                        setTimeout(() => {
                            setIsLockedOut(false);
                            localStorage.setItem('isLockedOut', 'false');
                            setUnlockPassword('');
                            setIsUnlocking(false);
                            setWakeProgress(0);
                        }, 600); // tempo para o smooth da animacao ate 100%
                    } catch (retryError) {
                        if (retryCount < maxRetries) { // maxRetries * 1s = 30s
                            setTimeout(retryLogin, 1000);
                        } else {
                            setWakeProgress(0);
                            setUnlockError('Servidor não respondeu a tempo. Atualize a página e tente novamente.');
                            setIsUnlocking(false);
                        }
                    }
                };
                setTimeout(retryLogin, 1000);
            } else {
                setUnlockError(error.message || 'Senha incorreta. Tente novamente.');
                setIsUnlocking(false);
            }
        }
    };
    // ----------------------------------------------

    useEffect(() => {
        localStorage.setItem('darkMode', JSON.stringify(darkMode));
        if (darkMode) {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    }, [darkMode]);

    // Rastrear 1 "Acesso" global por Sessão do Navegador (Visitantes ou Admins)
    useEffect(() => {
        const sessionTracked = sessionStorage.getItem('session_tracked_today');
        if (!sessionTracked) {
            // Usa setTimeout para garantir que o state statistics inicializou completamente do localStorage caso haja assincronia
            setTimeout(() => {
                updateStatistics('page_view', { username: 'Visitante' });
                sessionStorage.setItem('session_tracked_today', 'true');
            }, 1000);
        }
    }, []);

    useEffect(() => {
        console.log('Carregando dados JSON...');
        fetch('dados.json')
            .then(response => {
                console.log('Resposta recebida:', response.status);
                if (!response.ok) throw new Error('Falha ao carregar dados.json');
                return response.json();
            })
            .then(jsonData => {
                console.log('JSON carregado, número de itens:', jsonData.length);
                setData(jsonData);
                setFilteredData(jsonData);
            })
            .catch(error => {
                console.error('Erro ao carregar dados:', error);
            });

        // Opcional: sem ela a consulta funciona, só não mostra os códigos nacionais.
        fetch('lista-nacional.json')
            .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(setListaNacional)
            .catch(error => console.warn('Lista nacional da NFS-e indisponível:', error.message));
    }, []);

    // Local de incidência do ISS (art. 3º da LC 116/2003). A regra fica em incidencia-iss.js,
    // compartilhada com a API (/api/fiscal/search); o index.html carrega o arquivo antes deste.
    const getISSIncidenceLocation = (listLc) =>
        window.IncidenciaISS ? window.IncidenciaISS.localDeIncidencia(listLc) : 'Não disponível';

    // Busca na base ISS / CNAE. As regras ficam em busca-fiscal.js, compartilhadas com a
    // API (/api/fiscal/search); o index.html carrega o arquivo antes deste.
    const filterData = (term, mode = 'all') => window.BuscaFiscal.filtrar(data, term, mode, listaNacional);

    const handleSearch = (termo = searchTerm, mode = searchMode) => {
        const query = termo.trim();
        const results = filterData(termo, mode);
        setSearchResults(results);
        setLastQuery(query);

        if (query) {
            setRecentSearches(prev => {
                const next = [query, ...prev.filter(q => q.toLowerCase() !== query.toLowerCase())].slice(0, 5);
                try { localStorage.setItem(recentKey, JSON.stringify(next)); } catch (e) { /* armazenamento indisponível */ }
                return next;
            });
        }

        // Registrar pesquisa nas estatísticas
        updateStatistics('search', {
            searchMode: mode === 'all' ? 'combined' : mode,
            user: currentUser?.username || 'unknown',
            query: query || 'consulta vazia',
            results: results.length
        });
    };

    if (isSessionValidating) {
        return (
            <div className={`flex justify-center items-center h-screen w-full relative overflow-hidden ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                {/* Background decorative blobs */}
                <div className={`absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full mix-blend-multiply filter blur-[80px] opacity-70 animate-blob ${darkMode ? 'bg-blue-600/20' : 'bg-blue-300'}`}></div>
                <div className={`absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full mix-blend-multiply filter blur-[80px] opacity-70 animate-blob animation-delay-2000 ${darkMode ? 'bg-purple-600/20' : 'bg-purple-300'}`}></div>

                <div className="flex flex-col items-center justify-center p-8 z-10">
                    <div className="relative mb-8 mt-[-10vh]">
                        {/* Outer rotating ring */}
                        <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-blue-500/50 border-r-purple-500/50 w-24 h-24 animate-[spin_3s_linear_infinite] m-[-8px]"></div>
                        {/* Middle rotating ring */}
                        <div className="absolute inset-0 rounded-full border-4 border-transparent border-b-blue-400/50 border-l-purple-400/50 w-20 h-20 animate-[spin_2s_linear_infinite_reverse]"></div>
                        {/* Inner spinner */}
                        <div className="rounded-full h-20 w-20 border-4 border-gray-200 dark:border-gray-800 flex items-center justify-center bg-white dark:bg-gray-800 shadow-xl">
                            <svg className="w-8 h-8 text-blue-500 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                        </div>
                    </div>
                    <div className="text-center space-y-2 mt-4">
                        <h2 className={`text-xl font-bold tracking-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                            Validando Acesso Seguro
                        </h2>
                        <p className={`text-sm font-medium tracking-wide flex items-center justify-center gap-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                            <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                            Verificando credenciais no servidor...
                        </p>
                    </div>
                </div>
            </div>
        );
    }

    // Renderização condicional baseada na autenticação
    if (!isAuthenticated) {
        return (
            <LoginForm
                onLogin={handleLogin}
                darkMode={darkMode}
                wakeProgress={wakeProgress}
                setWakeProgress={setWakeProgress}
            />
        );
    }

    return (
        <div className="pc-app">

            {/* Overlay da Tela de Bloqueio por inatividade (Sobreposto na UI Atual) */}
            {isLockedOut && (
                <div className={`absolute inset-0 z-[100] flex items-center justify-center ${darkMode ? 'bg-gray-900/25' : 'bg-gray-500/10'} backdrop-blur-sm transition-all duration-300`}>
                    <div className={`max-w-md w-full p-8 rounded-3xl shadow-2xl ${darkMode ? 'bg-gray-800/80' : 'bg-white/80'} backdrop-blur-md animate-fadeInUp border ${darkMode ? 'border-gray-700/50' : 'border-white/50'}`}>
                        <div className="text-center mb-8">
                            <div className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center mb-6 shadow-lg ${darkMode ? 'bg-gradient-to-tr from-blue-600 to-purple-600' : 'bg-gradient-to-tr from-blue-500 to-purple-600'}`}>
                                <span className="text-white font-bold text-2xl tracking-widest">
                                    {currentUser?.name?.substring(0, 2).toUpperCase() || currentUser?.username.substring(0, 2).toUpperCase() || 'US'}
                                </span>
                            </div>
                            <h2 className={`text-2xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                Sessão Bloqueada
                            </h2>
                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                Devido à inatividade, sua sessão foi bloqueada por segurança. Digite sua senha para continuar.
                            </p>
                        </div>

                        <form onSubmit={handleUnlockSubmit} className="space-y-6">
                            <div>
                                <input
                                    type="password"
                                    required
                                    value={unlockPassword}
                                    onChange={(e) => setUnlockPassword(e.target.value)}
                                    placeholder="Digite sua senha"
                                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all duration-200 focus:ring-2 focus:ring-offset-0 focus:outline-none ${darkMode ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400 focus:border-blue-500 focus:ring-blue-500/30' : 'bg-white border-gray-200 text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-blue-500/20'}`}
                                />
                            </div>

                            {wakeProgress > 0 ? (
                                <div className="my-3 animate-fadeIn">
                                    <div className="flex justify-between items-center mb-1.5 px-1">
                                        <span className={`text-xs font-bold uppercase tracking-wide ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                                            Despertando Servidor
                                        </span>
                                        <span className={`text-xs font-bold ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                            {wakeProgress}%
                                        </span>
                                    </div>
                                    <div className={`h-2.5 w-full rounded-full overflow-hidden shadow-inner ${darkMode ? 'bg-gray-700/60' : 'bg-gray-100'}`}>
                                        <div
                                            className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-[2000ms] ease-out relative"
                                            style={{ width: `${wakeProgress}%` }}
                                        >
                                            <div className="absolute inset-0 bg-white/20 animate-pulse mix-blend-overlay"></div>
                                        </div>
                                    </div>
                                </div>
                            ) : unlockError && (
                                <div className={`text-sm font-medium p-3 rounded-xl text-center animate-pulse ${darkMode ? 'bg-red-900/30 text-red-400 border border-red-800' : 'bg-red-50 text-red-600 border border-red-200'}`}>
                                    {unlockError}
                                </div>
                            )}

                            <div className="flex flex-col gap-3">
                                <button
                                    type="submit"
                                    disabled={isUnlocking}
                                    className={`w-full py-3 rounded-xl font-bold text-white transition-all duration-200 shadow-md transform hover:-translate-y-0.5 ${darkMode ? 'bg-blue-600 hover:bg-blue-500' : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:opacity-90'} disabled:opacity-50 ${isUnlocking ? 'hidden' : 'block'}`}
                                >
                                    Desbloquear
                                </button>
                                <button
                                    type="button"
                                    onClick={handleLogout}
                                    className={`w-full text-sm font-medium py-2 transition-colors ${darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-500 hover:text-gray-800'}`}
                                >
                                    Fazer logoff
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Hack CSS Global Dinâmico para Cursor Grabbing - Exibido Apenas Durante o Arraste dos Banners */}
            {isDraggingBanners && (
                <style dangerouslySetInnerHTML={{
                    __html: `
                    * {
                        cursor: grabbing !important;
                        user-select: none !important;
                    }
                `}} />
            )}
            <Sidebar
                currentView={currentView}
                setCurrentView={setCurrentView}
                currentUser={currentUser}
                onLogout={handleLogout}
                sidebarMobileOpen={sidebarMobileOpen}
                onCloseSidebar={() => setSidebarMobileOpen(false)}
                pendingCount={pendingUsers.length}
            />
            {/* Overlay do menu lateral no mobile */}
            {sidebarMobileOpen && (
                <div
                    className="pc-side-overlay md:hidden"
                    onClick={() => setSidebarMobileOpen(false)}
                    aria-hidden="true"
                />
            )}
            {/* Modal de Escolha de Congelamento */}
            {freezeModalBanner && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
                    <div className={`w-full max-w-md p-6 rounded-2xl shadow-2xl transform transition-all scale-100 ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-100'}`}>
                        <h3 className={`text-xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                            Congelar Serviço
                        </h3>
                        <p className={`mb-6 text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                            Selecione o motivo para suspender o acesso ao serviço <strong>{BANNER_STATIC[freezeModalBanner.key]?.label || freezeModalBanner.label}</strong>.
                        </p>

                        <div className="grid grid-cols-1 gap-3">
                            <button
                                onClick={() => {
                                    handleFreezeToggleGlobal(freezeModalBanner, 'maintenance');
                                    setFreezeModalBanner(null);
                                }}
                                className={`flex items-center gap-4 p-4 rounded-xl border-2 transition-all group text-left ${darkMode ? 'border-gray-700 hover:border-red-500 hover:bg-red-500/10' : 'border-gray-200 hover:border-red-500 hover:bg-red-50'}`}
                            >
                                <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-red-500/20 text-red-400' : 'bg-red-100 text-red-600'}`}>
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>
                                </div>
                                <div>
                                    <h4 className={`font-bold ${darkMode ? 'text-white group-hover:text-red-400' : 'text-gray-900 group-hover:text-red-600'}`}>Em Manutenção</h4>
                                    <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Indisponibilidade temporária técnica.</p>
                                </div>
                            </button>

                            <button
                                onClick={() => {
                                    handleFreezeToggleGlobal(freezeModalBanner, 'construction');
                                    setFreezeModalBanner(null);
                                }}
                                className={`flex items-center gap-4 p-4 rounded-xl border-2 transition-all group text-left ${darkMode ? 'border-gray-700 hover:border-amber-500 hover:bg-amber-500/10' : 'border-gray-200 hover:border-amber-500 hover:bg-amber-50'}`}
                            >
                                <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-amber-500/20 text-amber-400' : 'bg-amber-100 text-amber-600'}`}>
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></svg>
                                </div>
                                <div>
                                    <h4 className={`font-bold ${darkMode ? 'text-white group-hover:text-amber-400' : 'text-gray-900 group-hover:text-amber-600'}`}>Em Construção</h4>
                                    <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Funcionalidade em desenvolvimento.</p>
                                </div>
                            </button>
                        </div>

                        <button
                            onClick={() => setFreezeModalBanner(null)}
                            className={`mt-6 w-full py-3 rounded-xl font-semibold transition-colors ${darkMode ? 'bg-gray-700 text-gray-300 hover:bg-gray-600' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
                        >
                            Cancelar
                        </button>
                    </div>
                </div>
            )}

            <div className="pc-scroll">
                <div>
                    <div className="pc-main" role="main">
                        <header className="pc-top">
                            <div className="pc-top-id">
                                <button
                                    type="button"
                                    onClick={() => setSidebarMobileOpen(true)}
                                    className="pc-iconbtn pc-only-mobile"
                                    aria-label="Abrir menu"
                                >
                                    <PcIcon name="menu" />
                                </button>
                                {currentView === 'home' ? (
                                    <div className="min-w-0">
                                        <p className="pc-top-date">{dataPorExtenso()}</p>
                                        <h1 className="pc-top-title">
                                            {saudacao()}{currentUser ? `, ${currentUser.name?.split(' ')[0] || currentUser.username}` : ''}
                                        </h1>
                                    </div>
                                ) : (
                                    <nav className="pc-crumbs" aria-label="Trilha">
                                        <button type="button" onClick={() => setCurrentView('home')}>Início</button>
                                        <span aria-hidden="true">/</span>
                                        <span aria-current="page">{VIEW_TITLES[currentView] || ''}</span>
                                    </nav>
                                )}
                            </div>

                            <div className="pc-top-tools">
                                <a
                                    href="https://app.bbgov360.com.br/atendimento?id=8340618"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="pc-iconbtn"
                                    aria-label="Atendimento Virtual"
                                >
                                    <span className="pc-mask-icon" style={{ '--icon': 'url("image/NextChat.png")' }} aria-hidden="true" />
                                    <span className="pc-tip">Atendimento Virtual</span>
                                </a>
                                <a
                                    href="https://mail.imperatriz.ma.gov.br/"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="pc-iconbtn"
                                    aria-label="E-mail Institucional"
                                >
                                    <PcIcon name="mail" size={18} />
                                    <span className="pc-tip">E-mail Institucional</span>
                                </a>
                                <button
                                    type="button"
                                    onClick={() => setDarkMode(!darkMode)}
                                    className="pc-iconbtn"
                                    aria-label={darkMode ? 'Ativar modo claro' : 'Ativar modo escuro'}
                                >
                                    <PcIcon name={darkMode ? 'sun' : 'moon'} size={18} />
                                    <span className="pc-tip">{darkMode ? 'Modo claro' : 'Modo escuro'}</span>
                                </button>
                            </div>
                        </header>

                        {/* Navegação condicional entre views */}
                        {currentView === 'profile' && (
                            <UserProfilePage
                                user={currentUser}
                                onLogout={handleLogout}
                                onCredentialsChanged={handleCredentialsChanged}
                                darkMode={darkMode}
                            />
                        )}

                        {(currentView === 'home' || currentView === 'outros' || currentView === 'other-services') && (() => {
                            // Início e Serviços Internos usam o mesmo painel de módulos.
                            const menu = currentView === 'home' ? 'home' : 'outros';
                            const isAdmin = currentUser?.role === 'admin';
                            const homeBanners = bannerConfig
                                .filter(b => BANNER_STATIC[b.key])
                                .filter(b => (BANNER_STATIC[b.key].menu || 'home') === menu)
                                .filter(b => isAdmin || b.enabled);

                            const track = (label) => updateStatistics('bannerClick', {
                                bannerLabel: label,
                                user: currentUser ? currentUser.username : 'Visitante'
                            });

                            // Subserviços de um card de grupo (abertos na folha). Lista completa, nunca truncada.
                            const subItemsFor = (banner, s) => {
                                const keys = banner.key === 'dte' ? DTE_SUB_BANNERS_KEYS : [];
                                if (keys.length) {
                                    return keys
                                        .filter(k => bannerConfig.find(bc => bc.key === k)?.enabled !== false)
                                        .map(k => {
                                            const sub = BANNER_STATIC[k];
                                            if (!sub) return null;
                                            return {
                                                id: k,
                                                label: sub.label,
                                                desc: sub.description,
                                                icon: sub.icon,
                                                imageIcon: sub.imageIcon,
                                                href: sub.isInternal ? null : sub.href,
                                                tag: sub.isInternal ? 'Interno' : 'Externo',
                                                onSelect: sub.isInternal ? () => setCurrentView(sub.view || 'search') : null
                                            };
                                        })
                                        .filter(Boolean);
                                }
                                if (s.modalId === 'biblioteca') {
                                    return BIBLIOTECA_CATEGORIAS.map(cat => ({
                                        id: cat.id,
                                        label: cat.label,
                                        desc: cat.description,
                                        icon: cat.icon,
                                        href: null,
                                        tag: `${cat.links.length} ${cat.links.length === 1 ? 'item' : 'itens'}`,
                                        onSelect: () => {
                                            setBibliotecaCategoria(cat.id);
                                            setBibliotecaModalOpen(true);
                                        }
                                    }));
                                }
                                return [];
                            };
                            const unidade = (banner) => BANNER_STATIC[banner.key]?.modalId === 'biblioteca' ? 'categorias' : 'serviços';

                            const tile = (s, size = 20) => (
                                <span className={`pc-tile ${s.imageIcon ? 'pc-tile--img' : ''}`}>
                                    {s.imageIcon ? (
                                        <img src={s.imageIcon} alt="" loading="lazy" />
                                    ) : (
                                        <svg width={size} height={size} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d={s.icon} />
                                        </svg>
                                    )}
                                </span>
                            );

                            const renderCard = (banner, index, secId) => {
                                const s = BANNER_STATIC[banner.key];
                                if (!s) return null;
                                const isDisabledForUser = !banner.enabled && !isAdmin;
                                const isFrozen = banner.isFrozen === true;
                                const isEffectivelyFrozen = isFrozen && !isAdmin;
                                const isInert = isDisabledForUser || s.comingSoon || isEffectivelyFrozen;
                                const subItems = subItemsFor(banner, s);
                                const isGroup = subItems.length > 0;
                                const isOpen = isGroup && openGroup === banner.key;
                                const isDropTarget = isAdmin && isDraggingBanners && dragOverBannerId === banner.id;
                                const label = s.label || banner.label;
                                const construcao = banner.freezeReason === 'construction';

                                // Índice no bannerConfig completo: é ele que handleSortBanners reordena.
                                // A seção vem de HOME_SECTIONS (fixa), então o arraste só vale dentro
                                // da própria seção; fora dela o card não é destino de soltura.
                                const configIndex = bannerConfig.findIndex(b => b.id === banner.id);
                                const mesmaSecao = () => dragSection.current === secId;
                                const dragProps = isAdmin ? {
                                    draggable: true,
                                    onDragStart: (e) => {
                                        dragItem.current = configIndex;
                                        dragSection.current = secId;
                                        e.dataTransfer.effectAllowed = 'move';
                                        e.dataTransfer.setData('text/plain', banner.key); // Firefox só inicia o arraste com dados
                                        e.currentTarget.classList.add('opacity-50');
                                        setIsDraggingBanners(true);
                                    },
                                    onDragEnter: () => {
                                        if (!mesmaSecao()) {
                                            dragOverItem.current = null;
                                            setDragOverBannerId(null);
                                            return;
                                        }
                                        dragOverItem.current = configIndex;
                                        setDragOverBannerId(banner.id);
                                    },
                                    onDragOver: (e) => {
                                        if (!mesmaSecao()) return; // sem preventDefault: cursor de "proibido"
                                        e.preventDefault();
                                        e.dataTransfer.dropEffect = 'move';
                                    },
                                    onDrop: (e) => e.preventDefault(),
                                    onDragEnd: (e) => {
                                        // Solto fora de um card válido (ou Esc): não reordena.
                                        if (e.dataTransfer.dropEffect === 'none') dragOverItem.current = null;
                                        e.currentTarget.classList.remove('opacity-50');
                                        dragSection.current = null;
                                        setIsDraggingBanners(false);
                                        setDragOverBannerId(null);
                                        handleSortBanners();
                                    }
                                } : {};

                                // Ação principal: um único elemento interativo, esticado sobre o card.
                                let action = <span>{label}</span>;
                                if (!isInert) {
                                    if (isGroup) {
                                        action = (
                                            <button
                                                type="button"
                                                className="pc-card-hit"
                                                aria-haspopup="dialog"
                                                aria-expanded={isOpen}
                                                onClick={() => setOpenGroup(banner.key)}
                                            >
                                                {label}
                                            </button>
                                        );
                                    } else if (s.isInternal) {
                                        action = (
                                            <button
                                                type="button"
                                                className="pc-card-hit"
                                                onClick={() => { track(label); setCurrentView(s.view || 'search'); }}
                                            >
                                                {label}
                                            </button>
                                        );
                                    } else {
                                        action = (
                                            <a
                                                href={s.href}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="pc-card-hit"
                                                draggable={false}
                                                onClick={() => track(label)}
                                            >
                                                {label}
                                            </a>
                                        );
                                    }
                                }

                                return (
                                    <div
                                        key={banner.id}
                                        className={`pc-card ${isGroup ? 'is-deck' : ''} ${isInert ? 'is-inert' : ''} ${isDisabledForUser ? 'is-muted' : ''} ${isOpen ? 'is-open' : ''} ${isDropTarget ? 'is-drop-target' : ''} ${isAdmin ? 'is-admin' : ''}`}
                                        style={{ '--accent': mosaicAccent(s.accent, darkMode), '--i': Math.min(index, 11) }}
                                        data-group-card={isGroup ? banner.key : undefined}
                                        {...dragProps}
                                    >
                                        <div className="pc-card-head">
                                            {tile(s)}
                                            {isAdmin ? (
                                                <div className="pc-admin">
                                                    <span className={`pc-badge ${isFrozen ? (construcao ? 'pc-badge--warn' : 'pc-badge--crit') : 'pc-badge--ok'}`}>
                                                        {isFrozen ? (construcao ? 'Em obras' : 'Revisão') : 'Ativo'}
                                                    </span>
                                                    <button
                                                        type="button"
                                                        role="switch"
                                                        aria-checked={isFrozen}
                                                        aria-label={isFrozen ? `Descongelar ${label}` : `Congelar ${label}`}
                                                        title={isFrozen ? 'Descongelar serviço' : 'Congelar serviço'}
                                                        className={`pc-switch ${isFrozen ? (construcao ? 'is-on-build' : 'is-on-maint') : ''}`}
                                                        onClick={(e) => {
                                                            e.preventDefault();
                                                            e.stopPropagation();
                                                            if (isFrozen) handleFreezeToggleGlobal(banner);
                                                            else setFreezeModalBanner(banner);
                                                        }}
                                                    />
                                                    <span title="Arraste para reordenar" style={{ color: 'var(--pc-muted)', display: 'inline-flex' }}>
                                                        <PcIcon name="grip" size={16} />
                                                    </span>
                                                </div>
                                            ) : (s.comingSoon && !isFrozen && (
                                                <span className="pc-badge pc-badge--warn">Em construção</span>
                                            ))}
                                        </div>

                                        <div className="pc-card-body">
                                            <h3 className="pc-card-title">{action}</h3>
                                            <p className="pc-card-desc">{s.description}</p>
                                        </div>

                                        <div className={`pc-card-foot ${isGroup ? 'is-group' : ''}`}>
                                            {isGroup ? (
                                                <>
                                                    <span className="pc-peek" aria-hidden="true">
                                                        {subItems.slice(0, 4).map(item => (
                                                            <React.Fragment key={item.id}>{tile(item, 13)}</React.Fragment>
                                                        ))}
                                                        {subItems.length > 4 && <span className="pc-peek-more">+{subItems.length - 4}</span>}
                                                    </span>
                                                    <span className="pc-peek-label">
                                                        {subItems.length} {unidade(banner)}
                                                        <PcIcon name="expand" size={15} />
                                                    </span>
                                                </>
                                            ) : (
                                                <>
                                                    {s.isInternal ? 'Ferramenta interna' : 'Abre em nova aba'}
                                                    {!isInert && <PcIcon name="arrowOut" size={16} />}
                                                </>
                                            )}
                                        </div>

                                        {isFrozen && !isAdmin && (
                                            <div className="pc-veil">
                                                <span className={`pc-badge ${construcao ? 'pc-badge--warn' : 'pc-badge--crit'}`}>
                                                    {construcao ? 'Em construção' : 'Em manutenção'}
                                                </span>
                                            </div>
                                        )}
                                    </div>
                                );
                            };

                            const baseSecoes = menu === 'home'
                                ? [...HOME_SECTIONS, { id: 'outros', title: 'Outros serviços', keys: null }]
                                : [{ id: 'internos', title: 'Serviços internos', keys: null }];
                            const secoes = baseSecoes
                                .map(sec => ({
                                    ...sec,
                                    banners: homeBanners.filter(b => sec.keys
                                        ? sec.keys.includes(b.key)
                                        : !HOME_SECTIONS.some(x => x.keys.includes(b.key)))
                                }))
                                .filter(sec => sec.banners.length > 0);
                            const grupoAberto = openGroup && homeBanners.find(b => b.key === openGroup);

                            return (
                                <div key={menu} className="flex flex-col gap-8 animate-fadeInUp">
                                    {secoes.map(sec => {
                                        return (
                                            <section
                                                key={sec.id}
                                                className={`pc-section ${isDraggingBanners && dragSection.current && dragSection.current !== sec.id ? 'is-drag-off' : ''}`}
                                                aria-labelledby={`secao-${sec.id}`}
                                            >
                                                <div className="pc-section-head">
                                                    <h2 id={`secao-${sec.id}`} className="pc-section-title">{sec.title}</h2>
                                                    <span className="pc-section-count">{sec.banners.length} {sec.banners.length === 1 ? 'módulo' : 'módulos'}</span>
                                                </div>
                                                <div className="pc-grid">
                                                    {sec.banners.map((banner, i) => renderCard(banner, i, sec.id))}
                                                </div>
                                            </section>
                                        );
                                    })}
                                    {grupoAberto && (() => {
                                        const s = BANNER_STATIC[grupoAberto.key];
                                        const items = subItemsFor(grupoAberto, s);
                                        return (
                                            <PcGroupSheet
                                                key={grupoAberto.key}
                                                groupKey={grupoAberto.key}
                                                title={s.label || grupoAberto.label}
                                                subtitle={`${items.length} ${unidade(grupoAberto)} · ${s.description}`}
                                                accent={mosaicAccent(s.accent, darkMode)}
                                                icon={s}
                                                items={items}
                                                renderTile={tile}
                                                onTrack={track}
                                                onClose={() => setOpenGroup(null)}
                                            />
                                        );
                                    })()}
                                </div>
                            );
                        })()}

                        {currentView === 'search' && (
                            <ConsultaIssCnae
                                data={data}
                                listaNacional={listaNacional}
                                searchTerm={searchTerm}
                                setSearchTerm={setSearchTerm}
                                mode={searchMode}
                                setMode={setSearchMode}
                                results={searchResults}
                                lastQuery={lastQuery}
                                onSearch={handleSearch}
                                recent={recentSearches}
                                getIncidence={getISSIncidenceLocation}
                            />
                        )}

                        {/* View Admin: Gestão de Usuários */}
                        {currentUser?.role === 'admin' && currentView === 'admin-users' && (
                            <div className="pc-page animate-fadeInUp">
                                <header className="pc-page-head">
                                    <div>
                                        <h1 className="pc-page-title">Usuários</h1>
                                        <p className="pc-page-lead">Aprove solicitações de acesso, redefina senhas e bloqueie ou exclua contas.</p>
                                    </div>
                                </header>

                                {pendingUsers.length > 0 && (
                                    <section className="pc-box pc-box--warn" aria-labelledby="usuarios-pendentes">
                                        <div className="pc-box-head">
                                            <div>
                                                <h2 id="usuarios-pendentes" className="pc-box-title">Solicitações pendentes</h2>
                                                <p className="pc-box-sub">
                                                    {pendingUsers.length === 1 ? '1 pessoa aguarda' : `${pendingUsers.length} pessoas aguardam`} aprovação para acessar o Ecossistema.
                                                </p>
                                            </div>
                                        </div>
                                        <ul className="pc-rows">
                                            {pendingUsers.map(user => (
                                                <li key={user.id} className="pc-row">
                                                    <span className="pc-avatar pc-avatar--warn">{(user.name || user.username || '?').charAt(0).toUpperCase()}</span>
                                                    <div className="pc-row-main">
                                                        <span className="pc-row-name">{user.name}</span>
                                                        <span className="pc-row-sub pc-mono">@{user.username}</span>
                                                    </div>
                                                    <div className="pc-row-actions">
                                                        <button type="button" className="pc-btn pc-btn--sm pc-btn--primary" onClick={() => handleAuthorizeUser(user.id)}>
                                                            <PcIcon name="check" size={15} />
                                                            Autorizar
                                                        </button>
                                                        <button
                                                            type="button"
                                                            className="pc-btn pc-btn--sm pc-btn--danger"
                                                            onClick={async () => {
                                                                if (confirm(`Rejeitar e excluir o cadastro de "${user.name}" (${user.username})?`)) {
                                                                    try {
                                                                        await ApiService.deleteUser(user.id);
                                                                        await loadPendingUsers();
                                                                        setAdminUsersListKey(k => k + 1);
                                                                    } catch (err) {
                                                                        alert('Erro ao rejeitar solicitação: ' + err.message);
                                                                    }
                                                                }
                                                            }}
                                                        >
                                                            <PcIcon name="close" size={15} />
                                                            Rejeitar
                                                        </button>
                                                    </div>
                                                </li>
                                            ))}
                                        </ul>
                                    </section>
                                )}

                                <AdminUsersTable
                                    adminUsersListKey={adminUsersListKey}
                                    onRefreshNeeded={() => {
                                        loadPendingUsers();
                                        setAdminUsersListKey(k => k + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* View Admin: Controle de Banners */}
                        {currentUser?.role === 'admin' && currentView === 'admin-banners' && (
                            <AdminBannersPanel darkMode={darkMode} />
                        )}

                        {/* Painel de Auditoria */}
                        {currentUser?.role === 'admin' && currentView === 'admin-dashboard' && (() => {
                            const pal = vizPal(darkMode);
                            const todos = statistics?.searchHistory || [];
                            const agora = Date.now();
                            const { inicio, range } = janelaAuditoria(todos, auditRange, agora);

                            // Uma única fatia alimenta TODOS os gráficos — a barra de filtros
                            // fica acima de tudo que ela escopa, nunca dentro de um card.
                            const naJanela = todos.filter(e => {
                                const t = new Date(e.timestamp).getTime();
                                return !isNaN(t) && t >= inicio && t <= agora;
                            });
                            const fatia = naJanela
                                .filter(e => auditUserFilter === '' || e.user === auditUserFilter)
                                .filter(e => {
                                    if (auditTypeFilter === '') return true;
                                    if (auditTypeFilter === 'banner') return ehServico(e);
                                    if (auditTypeFilter === 'login_failure') return ehFalha(e);
                                    if (auditTypeFilter === 'login') return ehLogin(e);
                                    if (auditTypeFilter === 'admin') return /^admin_|user_/.test(e.action || '');
                                    return true;
                                });

                            // Janela anterior de mesmo tamanho, para o delta dos tiles.
                            const largura = range.horas ? range.horas * 3600 * 1000 : null;
                            const anterior = largura
                                ? todos.filter(e => {
                                    const t = new Date(e.timestamp).getTime();
                                    return !isNaN(t) && t >= inicio - largura && t < inicio;
                                })
                                : [];
                            const pct = (atual, antes) => {
                                if (!largura) return null;
                                if (antes === 0) return atual === 0 ? 0 : 100;
                                return Math.round(((atual - antes) / antes) * 100);
                            };

                            const sessoes = fatia.filter(ehLogin).length;
                            const servicos = fatia.filter(ehServico).length;
                            const falhas = fatia.filter(ehFalha).length;
                            const ativos = new Set(fatia.map(e => e.user).filter(Boolean)).size;
                            const ips = new Set(fatia.map(e => e.ipAddress).filter(Boolean)).size;

                            const { bins, passo } = agrupaPorTempo(fatia, auditRange, agora);
                            const serie = bins.map(b => b.total);
                            const grade = mapaCalor(fatia);
                            const topServicos = ranking(fatia.filter(ehServico), e => e.bannerLabel);
                            const topUsuarios = ranking(fatia, e => e.user || 'Visitante');

                            // Sinais de segurança: 3+ falhas por origem na janela.
                            const grupos = {};
                            fatia.filter(ehFalha).forEach(e => {
                                const k = e.user || e.ipAddress || 'origem desconhecida';
                                (grupos[k] = grupos[k] || []).push(e);
                            });
                            const sinais = Object.entries(grupos)
                                .filter(([, itens]) => itens.length >= 3)
                                .map(([k, itens]) => ({
                                    origem: k,
                                    n: itens.length,
                                    nivel: itens.length >= 5 ? 'critical' : 'warning'
                                }))
                                .sort((a, b) => b.n - a.n);

                            const exportarCSV = () => {
                                if (!fatia.length) { alert('Nenhum evento na janela selecionada para exportar.'); return; }
                                const linhas = [['Timestamp', 'Usuario', 'Acao', 'Sucesso', 'IP', 'Detalhe']];
                                fatia.forEach(e => linhas.push([
                                    new Date(e.timestamp).toLocaleString('pt-BR'),
                                    e.user || 'Visitante',
                                    e.action || e.type || '-',
                                    ehFalha(e) ? 'Nao' : 'Sim',
                                    e.ipAddress || '-',
                                    e.bannerLabel || e.details?.reason || ''
                                ]));
                                const csv = linhas.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
                                const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = 'auditoria_' + auditRange + '_' + new Date().toISOString().split('T')[0] + '.csv';
                                a.click();
                                URL.revokeObjectURL(url);
                            };

                            return (
                            <div className={`viz-page hud ${darkMode ? 'is-dark' : ''} animate-fadeInUp`}>
                                {/* Cabeçalho */}
                                <header className="viz-head">
                                    <div className="viz-head-id">
                                        <span className="viz-head-icon" style={{ '--tone': pal.s1 }}>
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                                        </span>
                                        <div>
                                            <h2 className="viz-title">Central de Auditoria</h2>
                                            <p className="viz-sub">
                                                {fatia.length} evento{fatia.length === 1 ? '' : 's'} na janela · {ips} IP{ips === 1 ? '' : 's'} distinto{ips === 1 ? '' : 's'}
                                                {isAuditLoading && ' · atualizando…'}
                                            </p>
                                        </div>
                                    </div>
                                    <div className="viz-head-actions">
                                        <button onClick={exportarCSV} className="viz-btn" style={{ '--tone': pal.s1 }}>
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                                            Exportar CSV
                                        </button>
                                        <button
                                            onClick={async () => {
                                                if (!window.confirm('Isso apagará irreversivelmente todos os registros de auditoria no banco. Continuar?')) return;
                                                try {
                                                    setIsAuditLoading(true);
                                                    await ApiService.clearAuditLogs();
                                                    localStorage.removeItem('appStatistics');
                                                    setStatistics({ totalAccesses: 0, totalBannerClicks: 0, totalRegisteredUsers: 0, lastAccess: null, dailyAccesses: {}, searchHistory: [], userSessions: {}, bannerClicks: {} });
                                                    setAuditUserFilter('');
                                                } catch (e) {
                                                    alert('Erro ao limpar auditoria: ' + e.message);
                                                } finally {
                                                    setIsAuditLoading(false);
                                                }
                                            }}
                                            disabled={isAuditLoading}
                                            className="viz-btn"
                                            style={{ '--tone': pal.critical }}
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                                            Limpar
                                        </button>
                                    </div>
                                </header>

                                {pendingUsers.length > 0 && (
                                    <section className="pc-pending" aria-label="Solicitações pendentes">
                                        <span className="pc-pending-ico"><PcIcon name="userPlus" /></span>
                                        <div className="pc-pending-text">
                                            <strong>
                                                {pendingUsers.length === 1
                                                    ? '1 solicitação de acesso aguardando aprovação'
                                                    : `${pendingUsers.length} solicitações de acesso aguardando aprovação`}
                                            </strong>
                                            <span>{pendingUsers.slice(0, 3).map(u => u.username).join(', ')}{pendingUsers.length > 3 ? ' e outros' : ''}</span>
                                        </div>
                                        <button type="button" className="pc-btn pc-btn--ink" onClick={() => setCurrentView('admin-users')}>
                                            Revisar solicitações
                                        </button>
                                    </section>
                                )}

                                {/* Barra de filtros — uma só, acima de tudo que ela escopa */}
                                <div className="viz-filters">
                                    <div className="viz-range" role="group" aria-label="Período">
                                        {AUDIT_RANGES.map(r => (
                                            <button
                                                key={r.id}
                                                onClick={() => setAuditRange(r.id)}
                                                className={`viz-range-btn ${auditRange === r.id ? 'is-on' : ''}`}
                                                style={{ '--tone': pal.s1 }}
                                                aria-pressed={auditRange === r.id}
                                            >
                                                {r.label}
                                            </button>
                                        ))}
                                    </div>
                                    <select value={auditUserFilter} onChange={e => setAuditUserFilter(e.target.value)} className="viz-select">
                                        <option value="">Todos os usuários</option>
                                        {[...new Set(todos.map(a => a.user).filter(Boolean))].map(u => <option key={u} value={u}>{u}</option>)}
                                    </select>
                                    <select value={auditTypeFilter} onChange={e => setAuditTypeFilter(e.target.value)} className="viz-select">
                                        <option value="">Todos os eventos</option>
                                        <option value="banner">Acessos a serviços</option>
                                        <option value="login">Logins com sucesso</option>
                                        <option value="login_failure">Falhas</option>
                                        <option value="admin">Ações administrativas</option>
                                    </select>
                                </div>

                                {/* Sinais de segurança — cor de status sempre com ícone + rótulo */}
                                {sinais.length > 0 && (
                                    <div className="viz-signals">
                                        {sinais.slice(0, 3).map(s => (
                                            <div key={s.origem} className="viz-signal" style={{ '--tone': s.nivel === 'critical' ? pal.critical : pal.warning }}>
                                                <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                                                <span className="viz-signal-tag">{s.nivel === 'critical' ? 'Crítico' : 'Atenção'}</span>
                                                <span className="viz-signal-txt"><strong>{s.origem}</strong> — {s.n} falhas de autenticação na janela</span>
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {/* KPIs */}
                                <div className="viz-kpis">
                                    <VizStatTile rotulo="Sessões" valor={sessoes} delta={pct(sessoes, anterior.filter(ehLogin).length)}
                                        serie={serie} cor={pal.s1} nota="logins com sucesso" />
                                    <VizStatTile rotulo="Acessos a serviços" valor={servicos} delta={pct(servicos, anterior.filter(ehServico).length)}
                                        serie={bins.map(b => b.total)} cor={pal.s2} nota="cliques em banners" />
                                    <VizStatTile rotulo="Usuários ativos" valor={ativos} delta={pct(ativos, new Set(anterior.map(e => e.user).filter(Boolean)).size)}
                                        cor={pal.s1} nota="contas distintas na janela" />
                                    <VizStatTile rotulo="Falhas de autenticação" valor={falhas} delta={pct(falhas, anterior.filter(ehFalha).length)}
                                        cor={falhas > 0 ? pal.critical : pal.muted} nota="tentativas malsucedidas"
                                        statusCor={falhas > 0 ? pal.critical : undefined} />
                                    <VizStatTile rotulo="Base de usuários" valor={statistics?.totalRegisteredUsers || 0} delta={null}
                                        cor={pal.muted} nota="contas cadastradas" />
                                </div>

                                {/* Gráficos */}
                                <div className="viz-row">
                                    <figure className="viz-card">
                                        <figcaption className="viz-card-head">
                                            <h3 className="viz-card-title">Atividade por {passo}</h3>
                                            <p className="viz-card-sub">Total de eventos registrados</p>
                                        </figcaption>
                                        {fatia.length ? <VizTimeline bins={bins} passo={passo} pal={pal} />
                                            : <p className="viz-empty">Sem eventos na janela selecionada.</p>}
                                    </figure>

                                    <figure className="viz-card">
                                        <figcaption className="viz-card-head">
                                            <h3 className="viz-card-title">Janelas de uso</h3>
                                            <p className="viz-card-sub">Eventos por dia da semana e hora</p>
                                        </figcaption>
                                        {fatia.length ? <VizHeatmap grade={grade} pal={pal} />
                                            : <p className="viz-empty">Sem eventos na janela selecionada.</p>}
                                    </figure>
                                </div>

                                <div className="viz-row">
                                    <figure className="viz-card">
                                        <figcaption className="viz-card-head">
                                            <h3 className="viz-card-title">Serviços mais acessados</h3>
                                            <p className="viz-card-sub">Cliques em banners na janela</p>
                                        </figcaption>
                                        <VizRankBars dados={topServicos} cor={pal.s1} pal={pal} vazio="Nenhum serviço acessado na janela." />
                                    </figure>

                                    <figure className="viz-card">
                                        <figcaption className="viz-card-head">
                                            <h3 className="viz-card-title">Usuários mais ativos</h3>
                                            <p className="viz-card-sub">Eventos por conta na janela</p>
                                        </figcaption>
                                        <VizRankBars dados={topUsuarios} cor={pal.s2} pal={pal} vazio="Nenhuma atividade na janela." />
                                    </figure>
                                </div>

                                {/* Tabela — a leitura exata, sem depender de tooltip */}
                                <div className="viz-card viz-card--flush">
                                    <div className="viz-card-head viz-card-head--pad">
                                        <div>
                                            <h3 className="viz-card-title">Registro de eventos</h3>
                                            <p className="viz-card-sub">{fatia.length} registro{fatia.length === 1 ? '' : 's'} na janela e filtros atuais</p>
                                        </div>
                                    </div>
                                    <div className="viz-table-wrap custom-scrollbar">
                                        {fatia.length ? (
                                            <table className="viz-table">
                                                <thead>
                                                    <tr>
                                                        <th>Quando</th><th>Usuário</th><th>Evento</th><th>Origem</th><th>Detalhe</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {fatia.slice(0, 300).map((e, i) => {
                                                        const falhou = ehFalha(e);
                                                        return (
                                                            <tr key={i}>
                                                                <td className="viz-num">{new Date(e.timestamp).toLocaleString('pt-BR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</td>
                                                                <td className="viz-strong">{e.user || 'Visitante'}</td>
                                                                <td>
                                                                    <span className="viz-badge" style={{ '--tone': falhou ? pal.critical : pal.good }}>
                                                                        {falhou ? (
                                                                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" /></svg>
                                                                        ) : (
                                                                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" /></svg>
                                                                        )}
                                                                        {ehServico(e) ? 'Acesso a serviço' : ehLogin(e) ? 'Login' : falhou ? 'Falha' : (e.action || e.type)}
                                                                    </span>
                                                                </td>
                                                                <td className="viz-num">{e.ipAddress || '—'}</td>
                                                                <td className="viz-dim">{e.bannerLabel || e.details?.reason || e.details?.username || '—'}</td>
                                                            </tr>
                                                        );
                                                    })}
                                                </tbody>
                                            </table>
                                        ) : (
                                            <p className="viz-empty">Nenhum evento corresponde à janela e aos filtros atuais.</p>
                                        )}
                                    </div>
                                    {fatia.length > 300 && (
                                        <p className="viz-table-foot">Mostrando os 300 mais recentes de {fatia.length}. Use o CSV para a lista completa.</p>
                                    )}
                                </div>


                                {/* Configurações de Segurança */}
                                <div className="viz-card">
                                    <div className="flex items-center gap-3 mb-4">
                                        <span className="viz-head-icon" style={{ '--tone': pal.s1, width: '2rem', height: '2rem' }}>
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                                        </span>
                                        <h3 className="viz-card-title">Configurações de Segurança</h3>
                                    </div>
                                    
                                    <div className="space-y-4">
                                        <div>
                                            <p className={`text-xs font-semibold mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Tempo de Tolerância para Bloqueio por Inatividade</p>
                                            <p className={`text-xs mb-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Defina o tempo de inatividade permitido antes que a sessão do usuário seja temporariamente bloqueada por segurança.</p>
                                            
                                            <div className="flex flex-wrap gap-2 mb-4">
                                                {[
                                                    { label: '5 Minutos', value: '5' },
                                                    { label: '20 Minutos', value: '20' },
                                                    { label: '30 Minutos', value: '30' },
                                                    { label: '50 Minutos', value: '50' },
                                                    { label: 'Livre (Sem Bloqueio)', value: 'free' },
                                                    { label: 'Personalizado', value: 'custom' }
                                                ].map(opt => {
                                                    const isSelected = opt.value === 'custom' 
                                                        ? (lockscreenTimeout !== '5' && lockscreenTimeout !== '20' && lockscreenTimeout !== '30' && lockscreenTimeout !== '50' && lockscreenTimeout !== 'free')
                                                        : lockscreenTimeout === opt.value;
                                                    
                                                    return (
                                                        <button
                                                            key={opt.value}
                                                            type="button"
                                                            onClick={() => {
                                                                if (opt.value === 'custom') {
                                                                    setTempTimeoutVal(
                                                                        (lockscreenTimeout !== '5' && lockscreenTimeout !== '20' && lockscreenTimeout !== '30' && lockscreenTimeout !== '50' && lockscreenTimeout !== 'free')
                                                                            ? lockscreenTimeout
                                                                            : '15'
                                                                    );
                                                                } else {
                                                                    setTempTimeoutVal(opt.value);
                                                                    handleSaveTimeout(opt.value);
                                                                }
                                                            }}
                                                            className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all border ${
                                                                isSelected 
                                                                    ? 'bg-indigo-600 border-indigo-600 text-white shadow-sm'
                                                                    : (darkMode ? 'bg-gray-700/50 border-gray-600/50 text-gray-300 hover:bg-gray-700' : 'bg-gray-50 border-gray-200 text-gray-600 hover:bg-gray-100')
                                                            }`}
                                                        >
                                                            {opt.label}
                                                        </button>
                                                    );
                                                })}
                                            </div>

                                            {/* Input para valor personalizado */}
                                            {((lockscreenTimeout !== '5' && lockscreenTimeout !== '20' && lockscreenTimeout !== '30' && lockscreenTimeout !== '50' && lockscreenTimeout !== 'free') || (tempTimeoutVal !== '5' && tempTimeoutVal !== '20' && tempTimeoutVal !== '30' && tempTimeoutVal !== '50' && tempTimeoutVal !== 'free')) && (
                                                <div className="flex items-center gap-3 animate-fadeInUp mt-2">
                                                    <div className="relative max-w-[140px]">
                                                        <input
                                                            type="number"
                                                            min="1"
                                                            max="1440"
                                                            value={isNaN(parseInt(tempTimeoutVal)) ? '' : parseInt(tempTimeoutVal)}
                                                            onChange={(e) => setTempTimeoutVal(e.target.value)}
                                                            placeholder="Minutos"
                                                            className={`w-full text-xs font-bold rounded-xl pl-3 pr-10 py-2 border outline-none transition-colors ${
                                                                darkMode 
                                                                    ? 'bg-gray-800 border-gray-700 text-white focus:border-indigo-500' 
                                                                    : 'bg-white border-gray-200 text-gray-900 focus:border-indigo-600'
                                                            }`}
                                                        />
                                                        <span className={`absolute right-3 top-2 text-xs font-semibold ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>min</span>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleSaveTimeout(tempTimeoutVal)}
                                                        disabled={isSavingTimeout}
                                                        className={`px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                                                            darkMode ? 'bg-indigo-600 text-white hover:bg-indigo-500' : 'bg-indigo-600 text-white hover:bg-indigo-700'
                                                        } ${isSavingTimeout ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                    >
                                                        {isSavingTimeout ? 'Salvando...' : 'Salvar'}
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                            );
                        })()}

                        {/* Modal Bento Box — Biblioteca */}
                        {bibliotecaModalOpen && (() => {
                            const categoriaAtual = bibliotecaCategoria
                                ? BIBLIOTECA_CATEGORIAS.find(c => c.id === bibliotecaCategoria)
                                : null;
                            return (
                                <div
                                    className="fixed inset-0 z-50 flex items-center justify-center p-4"
                                    style={{ backgroundColor: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(6px)' }}
                                    onClick={() => { setBibliotecaModalOpen(false); setBibliotecaCategoria(null); setBibliotecaSearch(''); }}
                                >
                                    <div
                                        className={`relative w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden animate-fadeInUp ${darkMode ? 'bg-gray-900 border border-gray-700/60' : 'bg-white border border-amber-100'}`}
                                        onClick={e => e.stopPropagation()}
                                    >
                                        {/* Header */}
                                        <div className={`flex items-center justify-between px-6 py-5 border-b ${darkMode ? 'border-gray-700/60 bg-gradient-to-r from-amber-900/50 to-yellow-900/40' : 'border-amber-100 bg-gradient-to-r from-amber-50 to-yellow-50'}`}>
                                            <div className="flex items-center gap-3">
                                                {categoriaAtual ? (
                                                    <button
                                                        onClick={() => { setBibliotecaCategoria(null); setBibliotecaSearch(''); }}
                                                        className={`flex items-center gap-1.5 text-sm font-semibold px-3 py-1.5 rounded-lg transition-colors mr-1 ${darkMode ? 'bg-amber-500/10 text-amber-400 hover:bg-amber-500/20' : 'bg-amber-100 text-amber-700 hover:bg-amber-200'}`}
                                                    >
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
                                                        Voltar
                                                    </button>
                                                ) : (
                                                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-amber-500/20 text-amber-400' : 'bg-amber-100 text-amber-700'}`}>
                                                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" /></svg>
                                                    </div>
                                                )}
                                                <div>
                                                    <h2 className={`text-lg font-bold leading-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                        {categoriaAtual ? categoriaAtual.label : 'Biblioteca'}
                                                    </h2>
                                                    <p className={`text-xs ${darkMode ? 'text-amber-400/70' : 'text-amber-600'}`}>
                                                        {categoriaAtual ? `${categoriaAtual.links.length} ${categoriaAtual.links.length === 1 ? 'item disponível' : 'itens disponíveis'}` : 'Selecione uma categoria ou pesquise'}
                                                    </p>
                                                </div>
                                            </div>
                                            <button
                                                onClick={() => { setBibliotecaModalOpen(false); setBibliotecaCategoria(null); setBibliotecaSearch(''); }}
                                                className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors flex-shrink-0 ${darkMode ? 'text-gray-400 hover:bg-gray-700 hover:text-white' : 'text-gray-500 hover:bg-white/80 hover:text-gray-900'}`}
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                                            </button>
                                        </div>

                                        {/* Barra de Busca — só no grid (nível 1) */}
                                        {!categoriaAtual && (
                                            <div className="px-5 pt-4 pb-1">
                                                <div className="relative">
                                                    <svg className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                                                    <input
                                                        type="text"
                                                        value={bibliotecaSearch}
                                                        onChange={e => setBibliotecaSearch(e.target.value)}
                                                        placeholder="Buscar em todas as categorias..."
                                                        className={`w-full pl-9 pr-9 py-2.5 text-sm rounded-xl border transition-all duration-200 focus:outline-none focus:ring-2 ${darkMode
                                                            ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-amber-500 focus:ring-amber-500/20'
                                                            : 'bg-gray-50 border-gray-200 text-gray-900 placeholder-gray-400 focus:border-amber-400 focus:ring-amber-400/20'
                                                            }`}
                                                    />
                                                    {bibliotecaSearch && (
                                                        <button
                                                            onClick={() => setBibliotecaSearch('')}
                                                            className={`absolute right-3 top-1/2 -translate-y-1/2 ${darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-700'}`}
                                                        >
                                                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" /></svg>
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                        )}

                                        {/* Helper de badge — cores semânticas */}
                                        {(() => {
                                            const badgeColors = {
                                                'Novo': darkMode ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-green-100 text-green-700 border border-green-200',
                                                'Atualizado': darkMode ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'bg-blue-100 text-blue-700 border border-blue-200',
                                                'PDF': darkMode ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-red-100 text-red-700 border border-red-200',
                                                'Em breve': darkMode ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-amber-100 text-amber-700 border border-amber-200',
                                                'Site Externo': darkMode ? 'bg-gray-700 text-gray-300 border border-gray-600' : 'bg-gray-100 text-gray-600 border border-gray-200',
                                            };
                                            const BadgeChip = ({ badge }) => badge
                                                ? <span className={`flex-shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded-md uppercase tracking-wide ${badgeColors[badge] || badgeColors['Site Externo']}`}>{badge}</span>
                                                : null;

                                            const LinkRow = ({ link, cat }) => {
                                                const isPlaceholder = !link.href || link.href === '#';
                                                return (
                                                    <a
                                                        href={isPlaceholder ? undefined : link.href}
                                                        target={isPlaceholder ? undefined : '_blank'}
                                                        rel="noopener noreferrer"
                                                        onClick={isPlaceholder ? e => e.preventDefault() : undefined}
                                                        className={`group flex items-center gap-3 p-3.5 rounded-xl border transition-all duration-200 ${isPlaceholder ? 'opacity-40 cursor-not-allowed pointer-events-none' : 'cursor-pointer hover:-translate-y-0.5 hover:shadow-md'} ${darkMode ? `bg-gradient-to-r ${cat.colorDark}` : `bg-gradient-to-r ${cat.colorLight}`}`}
                                                    >
                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${darkMode ? cat.iconDark : cat.iconLight}`}>
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
                                                        </div>
                                                        <div className="flex-1 min-w-0">
                                                            <div className="flex items-center gap-2">
                                                                <p className={`text-sm font-bold truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{link.label}</p>
                                                                <BadgeChip badge={link.badge} />
                                                            </div>
                                                            <p className={`text-xs mt-0.5 truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{link.description}</p>
                                                        </div>
                                                        {!isPlaceholder && (
                                                            <svg className={`w-4 h-4 flex-shrink-0 opacity-40 group-hover:opacity-100 transition-opacity ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                                                        )}
                                                    </a>
                                                );
                                            };

                                            // Estado de Busca Ativa: lista plana filtrada em todas as categorias
                                            if (!categoriaAtual && bibliotecaSearch.trim()) {
                                                const query = bibliotecaSearch.trim().toLowerCase();
                                                const resultados = BIBLIOTECA_CATEGORIAS.flatMap(cat =>
                                                    cat.links
                                                        .filter(l => l.label.toLowerCase().includes(query) || l.description.toLowerCase().includes(query))
                                                        .map(l => ({ link: l, cat }))
                                                );
                                                return (
                                                    <div className="p-5 space-y-3 max-h-[340px] overflow-y-auto custom-scrollbar">
                                                        {resultados.length > 0 ? resultados.map(({ link, cat }) => (
                                                            <div key={link.id}>
                                                                <p className={`text-[10px] font-bold uppercase tracking-widest mb-1.5 ml-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{cat.label}</p>
                                                                <LinkRow link={link} cat={cat} />
                                                            </div>
                                                        )) : (
                                                            <div className={`flex flex-col items-center justify-center py-10 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                                <svg className="w-8 h-8 mb-2 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                                                                <p className="text-sm font-medium">Nenhum resultado para "{bibliotecaSearch}"</p>
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            }

                                            // Estado A: Grid Bento Box
                                            if (!categoriaAtual) {
                                                return (
                                                    <div className="p-5 grid grid-cols-2 gap-3" style={{ gridAutoRows: 'minmax(110px, auto)' }}>
                                                        {BIBLIOTECA_CATEGORIAS.map(cat => (
                                                            <button
                                                                key={cat.id}
                                                                onClick={() => setBibliotecaCategoria(cat.id)}
                                                                className={`group relative flex flex-col items-start justify-between p-4 rounded-xl border-2 bg-gradient-to-br text-left transition-all duration-200 hover:-translate-y-1 hover:shadow-lg active:scale-[0.98] ${cat.size === 'wide' ? 'col-span-2' : ''} ${darkMode ? cat.colorDark : cat.colorLight}`}
                                                            >
                                                                <div className="flex items-start justify-between w-full gap-2">
                                                                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 transition-transform duration-200 group-hover:scale-110 ${darkMode ? cat.iconDark : cat.iconLight}`}>
                                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.75} d={cat.icon} /></svg>
                                                                    </div>
                                                                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full flex-shrink-0 ${darkMode ? 'bg-white/10 text-gray-300' : 'bg-white/60 text-gray-600'}`}>
                                                                        {cat.links.length} {cat.links.length === 1 ? 'item' : 'itens'}
                                                                    </span>
                                                                </div>
                                                                <div className="mt-2">
                                                                    <p className={`text-sm font-bold leading-snug ${darkMode ? 'text-white' : 'text-gray-900'}`}>{cat.label}</p>
                                                                    <p className={`text-xs mt-0.5 line-clamp-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{cat.description}</p>
                                                                </div>
                                                                <div className={`absolute bottom-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity ${darkMode ? 'text-amber-400' : 'text-amber-600'}`}>
                                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                                                                </div>
                                                            </button>
                                                        ))}
                                                    </div>
                                                );
                                            }

                                            // Estado B: Lista de Links da Categoria com Badges
                                            return (
                                                <div className="p-5 space-y-2 max-h-80 overflow-y-auto custom-scrollbar">
                                                    {categoriaAtual.links.map(link => (
                                                        <LinkRow key={link.id} link={link} cat={categoriaAtual} />
                                                    ))}
                                                </div>
                                            );
                                        })()}

                                        {/* Rodapé informativo quando há links placeholder */}
                                        {categoriaAtual && categoriaAtual.links.some(l => !l.href || l.href === '#') && (
                                            <p className={`pb-4 text-center text-xs ${darkMode ? 'text-gray-600' : 'text-gray-400'}`}>
                                                Links marcados como indisponíveis aguardam configuração.
                                            </p>
                                        )}
                                    </div>
                                </div>
                            );
                        })()}

                        <footer className="pc-footer">
                            © 2026 Ecossistema DIAAF · Murilo Miguel
                        </footer>

                    </div>
                </div >
            </div >
        </div >
    );
}

(function mountApp() {
    if (window.__USE_HTTP_SERVER__ === false) return;
    var rootElement = document.getElementById('root');
    if (!rootElement) return;
    var fallback = document.getElementById('load-fallback');
    try {
        if (typeof React === 'undefined' || typeof ReactDOM === 'undefined') {
            throw new Error('React ou ReactDOM não carregaram. Verifique sua conexão com a internet.');
        }
        window.__APP_LOADED__ = true;
        var root = ReactDOM.createRoot(rootElement);
        root.render(<ErrorBoundary><App /></ErrorBoundary>);
        if (fallback) fallback.style.display = 'none';
    } catch (err) {
        window.__APP_LOAD_FAILED__ = true;
        if (fallback) {
            fallback.style.display = 'block';
            var msgEl = document.getElementById('load-error-msg');
            if (msgEl) msgEl.textContent = (err && (err.message || err.toString())) || 'Erro ao carregar a aplicação.';
        }
        console.error('Erro ao renderizar:', err);
    }
})();
