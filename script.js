const { useState, useEffect, useRef } = React;

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
            localStorage.removeItem('authToken');
            localStorage.removeItem('currentUser');
            localStorage.removeItem('isAuthenticated');
            return null;
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

    const inputBase = `w-full px-4 py-3 rounded-xl border-2 transition-all duration-200 focus:ring-2 focus:ring-offset-0 focus:outline-none ${darkMode ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400 focus:border-blue-500 focus:ring-blue-500/30' : 'bg-white border-gray-200 text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-blue-500/20'}`;
    const inputError = 'border-red-500 focus:border-red-500 focus:ring-red-500/30';

    return (
        <div className={`rounded-3xl overflow-hidden animate-fadeInUp shadow-2xl ${darkMode ? 'bg-gray-800 border-gray-700/50' : 'bg-white border-gray-100'} border`}>
            {/* Cabeçalho Premium com glassmorphism e glow */}
            <div className={`relative py-12 px-8 overflow-hidden ${darkMode ? 'bg-gradient-to-r from-gray-900 via-blue-900/40 to-gray-900' : 'bg-gradient-to-r from-blue-600 via-blue-500 to-indigo-700'}`}>
                <div className="absolute inset-0 bg-white opacity-5 mix-blend-overlay pointer-events-none"></div>
                {/* Glow effects */}
                <div className="absolute top-0 left-1/4 w-64 h-64 bg-blue-500/30 rounded-full mix-blend-multiply filter blur-3xl opacity-50 animate-pulse"></div>
                <div className="absolute top-0 right-1/4 w-64 h-64 bg-cyan-500/30 rounded-full mix-blend-multiply filter blur-3xl opacity-50 animate-pulse" style={{ animationDelay: '2s' }}></div>

                <div className="relative flex flex-col md:flex-row items-center gap-8 z-10 max-w-5xl mx-auto">
                    <div className="relative group">
                        <div className={`absolute -inset-0.5 rounded-full blur opacity-50 group-hover:opacity-100 transition duration-500 ${darkMode ? 'bg-gradient-to-r from-blue-400 to-cyan-500' : 'bg-gradient-to-r from-white/50 to-white/30'}`}></div>
                        <div className={`relative w-28 h-28 rounded-full flex items-center justify-center text-5xl font-extrabold shadow-2xl ring-4 ${darkMode ? 'ring-gray-800 bg-gray-900 text-transparent bg-clip-text bg-gradient-to-br from-blue-400 to-cyan-400' : 'ring-white/40 bg-white/20 backdrop-blur-md text-white'}`}>
                            {(user.name || user.username || 'U').charAt(0).toUpperCase()}
                        </div>
                    </div>

                    <div className="flex-1 text-center md:text-left">
                        <h2 className={`text-3xl sm:text-4xl font-extrabold tracking-tight drop-shadow-sm ${darkMode ? 'text-white' : 'text-white'}`}>
                            {user.name || user.username || 'Meu Perfil'}
                        </h2>
                        <div className="flex flex-wrap items-center justify-center md:justify-start gap-3 mt-4">
                            <span className={`px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wider backdrop-blur-md border ${user.role === 'admin' ? (darkMode ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-amber-400/30 text-amber-50 border-amber-300/50') : (darkMode ? 'bg-blue-500/20 text-blue-300 border-blue-500/30' : 'bg-blue-400/30 text-blue-50 border-blue-300/50')}`}>
                                {user.role === 'admin' ? 'Administrador' : 'Usuário'}
                            </span>
                            <span className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-blue-100'}`}>
                                @{user.username}
                            </span>
                        </div>
                    </div>

                    <div>
                        <button
                            onClick={onLogout}
                            className={`group relative inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl font-medium transition-all duration-300 overflow-hidden shadow-lg backdrop-blur-md border ${darkMode ? 'bg-gray-800/50 hover:bg-red-500/20 text-gray-300 hover:text-red-400 border-gray-700 hover:border-red-500/30' : 'bg-white/10 hover:bg-white text-white hover:text-red-600 border-white/30 hover:border-white shadow-[0_0_15px_rgba(255,255,255,0.1)]'}`}
                        >
                            <span className="relative z-10 flex items-center gap-2">
                                <svg className={`w-5 h-5 transition-transform group-hover:-translate-x-1`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                </svg>
                                Desconectar
                            </span>
                        </button>
                    </div>
                </div>
            </div>

            {/* Mensagens de feedback */}
            {successMessage && (
                <div className={`mx-6 mt-6 p-4 rounded-xl flex items-center gap-3 ${darkMode ? 'bg-green-900/30 border border-green-700 text-green-300' : 'bg-green-50 border border-green-200 text-green-800'}`}>
                    <svg className="w-5 h-5 flex-shrink-0 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="font-medium">{successMessage}</span>
                </div>
            )}
            {errors.general && (
                <div className={`mx-6 mt-6 p-4 rounded-xl flex items-center gap-3 ${darkMode ? 'bg-red-900/30 border border-red-700 text-red-300' : 'bg-red-50 border border-red-200 text-red-800'}`}>
                    <svg className="w-5 h-5 flex-shrink-0 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="font-medium">{errors.general}</span>
                </div>
            )}

            {/* Conteúdo: informações ou formulário */}
            <div className={`p-8 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50/50'}`}>
                {!isEditing ? (
                    <div className="animate-fadeIn">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
                            <h3 className={`text-xl font-bold flex items-center gap-3 ${darkMode ? 'text-white' : 'text-gray-800'}`}>
                                <div className={`p-2 rounded-lg ${darkMode ? 'bg-blue-900/50 text-blue-400' : 'bg-blue-100 text-blue-600'}`}>
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                    </svg>
                                </div>
                                Dados da Conta
                            </h3>
                            <button
                                onClick={() => setIsEditing(true)}
                                className={`inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl font-semibold transition-all duration-300 transform hover:-translate-y-0.5 shadow-md hover:shadow-lg ${darkMode ? 'bg-blue-600 hover:bg-blue-500 text-white border-none' : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white border-none'}`}
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                </svg>
                                Editar Perfil
                            </button>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                            {[
                                { label: 'Nome Completo', value: user.name || 'Não informado', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z', color: 'blue' },
                                { label: 'Endereço de Email', value: user.email || 'Não informado', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z', color: 'purple' },
                                { label: 'Nome de Usuário', value: '@' + user.username, icon: 'M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z', color: 'indigo' },
                                { label: 'Último Acesso', value: user.lastLogin ? new Date(user.lastLogin).toLocaleString('pt-BR') : 'Primeiro acesso', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z', color: 'emerald' },
                                { label: 'Modificação de Senha', value: user.lastPasswordChange ? new Date(user.lastPasswordChange).toLocaleString('pt-BR') : 'Nunca alterada', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z', color: 'amber' }
                            ].map((item, i) => {
                                const colors = {
                                    blue: darkMode ? 'bg-blue-900/30 text-blue-400 border-blue-800/50' : 'bg-blue-50 text-blue-600 border-blue-100',
                                    purple: darkMode ? 'bg-purple-900/30 text-purple-400 border-purple-800/50' : 'bg-purple-50 text-purple-600 border-purple-100',
                                    indigo: darkMode ? 'bg-indigo-900/30 text-indigo-400 border-indigo-800/50' : 'bg-indigo-50 text-indigo-600 border-indigo-100',
                                    emerald: darkMode ? 'bg-emerald-900/30 text-emerald-400 border-emerald-800/50' : 'bg-emerald-50 text-emerald-600 border-emerald-100',
                                    amber: darkMode ? 'bg-amber-900/30 text-amber-400 border-amber-800/50' : 'bg-amber-50 text-amber-600 border-amber-100',
                                };
                                const iconClass = colors[item.color];

                                return (
                                    <div key={i} className={`p-6 rounded-2xl border transition-all duration-300 hover:-translate-y-1 hover:shadow-lg ${darkMode ? 'bg-gray-800/60 border-gray-700/50 hover:border-gray-600 hover:bg-gray-800/90' : 'bg-white border-gray-100 hover:border-gray-200 shadow-sm hover:shadow-md'}`}>
                                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-5 border ${iconClass}`}>
                                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={item.icon} /></svg>
                                        </div>
                                        <p className={`text-xs font-bold uppercase tracking-wider mb-1.5 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{item.label}</p>
                                        <p className={`font-semibold text-lg truncate ${darkMode ? 'text-gray-200' : 'text-gray-800'}`} title={item.value}>{item.value}</p>
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                ) : (
                    <div className="animate-fadeIn">
                        <div className="flex items-center justify-between mb-8">
                            <h3 className={`text-xl font-bold flex items-center gap-3 ${darkMode ? 'text-white' : 'text-gray-800'}`}>
                                <div className={`p-2 rounded-lg ${darkMode ? 'bg-blue-900/50 text-blue-400' : 'bg-blue-100 text-blue-600'}`}>
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                    </svg>
                                </div>
                                Editar Informações
                            </h3>
                        </div>

                        <form onSubmit={handleSubmit} className="space-y-8">
                            {/* Secao de dados basicos */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className={`block text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Nome Completo</label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                            <svg className={`h-5 w-5 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                                        </div>
                                        <input type="text" value={formData.name} onChange={(e) => handleInputChange('name', e.target.value)} disabled={isLoading}
                                            className={`pl-11 ${inputBase} ${errors.name ? inputError : ''}`} placeholder="Seu nome completo" />
                                    </div>
                                    {errors.name && <p className="text-sm font-medium text-red-500 animate-fadeIn">{errors.name}</p>}
                                </div>
                                <div className="space-y-2">
                                    <label className={`block text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Endereço de Email</label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                            <svg className={`h-5 w-5 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                                        </div>
                                        <input type="email" value={formData.email} onChange={(e) => handleInputChange('email', e.target.value)} disabled={isLoading}
                                            className={`pl-11 ${inputBase} ${errors.email ? inputError : ''}`} placeholder="seu@email.com" />
                                    </div>
                                    {errors.email && <p className="text-sm font-medium text-red-500 animate-fadeIn">{errors.email}</p>}
                                </div>
                                <div className="space-y-2 md:col-span-2">
                                    <label className={`block text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Nome de Usuário</label>
                                    <div className="relative">
                                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                            <svg className={`h-5 w-5 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                        </div>
                                        <input type="text" value={formData.username} onChange={(e) => handleInputChange('username', e.target.value)} disabled={isLoading}
                                            className={`pl-11 ${inputBase} ${errors.username ? inputError : ''}`} placeholder="usuario" />
                                    </div>
                                    {errors.username && <p className="text-sm font-medium text-red-500 animate-fadeIn">{errors.username}</p>}
                                </div>
                            </div>

                            {/* Secao de Seguranca Destacada */}
                            <div className={`p-6 md:p-8 rounded-2xl border transition-all ${darkMode ? 'bg-gray-800/80 border-gray-700/80 hover:border-indigo-500/50' : 'bg-gray-50/80 border-gray-200 hover:border-indigo-300'} mt-8 relative overflow-hidden group`}>
                                <div className={`absolute top-0 left-0 w-1.5 h-full ${darkMode ? 'bg-indigo-500/80 group-hover:bg-indigo-400' : 'bg-indigo-500 group-hover:bg-indigo-600'} transition-colors`}></div>

                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-2">
                                    <div className="flex items-center gap-4">
                                        <div className={`p-3 rounded-xl ${darkMode ? 'bg-indigo-900/40 text-indigo-400' : 'bg-white shadow-sm border border-indigo-100 text-indigo-600'}`}>
                                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                                        </div>
                                        <div>
                                            <h4 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-800'}`}>Segurança da Conta</h4>
                                            <p className={`text-sm mt-0.5 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Gerencie sua senha de acesso</p>
                                        </div>
                                    </div>
                                    <label className="relative inline-flex items-center cursor-pointer">
                                        <input type="checkbox" className="sr-only peer" checked={showPasswordFields} onChange={(e) => setShowPasswordFields(e.target.checked)} disabled={isLoading} />
                                        <div className={`w-12 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-indigo-300 dark:peer-focus:ring-indigo-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 ${darkMode ? 'peer-checked:bg-indigo-500' : 'peer-checked:bg-indigo-600'}`}></div>
                                        <span className={`ml-3 text-sm font-semibold ${darkMode ? (showPasswordFields ? 'text-indigo-400' : 'text-gray-500') : (showPasswordFields ? 'text-indigo-600' : 'text-gray-500')}`}>{showPasswordFields ? 'Visível' : 'Oculto'}</span>
                                    </label>
                                </div>

                                {showPasswordFields && (
                                    <div className={`mt-8 pt-8 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'} grid grid-cols-1 md:grid-cols-2 gap-6 animate-fadeInDown`}>
                                        <div className="space-y-2 md:col-span-2">
                                            <label className={`block text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Senha Atual</label>
                                            <input type="password" value={formData.currentPassword} onChange={(e) => handleInputChange('currentPassword', e.target.value)} disabled={isLoading}
                                                className={`${inputBase} ${errors.currentPassword ? inputError : ''}`} placeholder="Requisitada para confirmar sua identidade" />
                                            {errors.currentPassword && <p className="text-sm font-medium text-red-500 animate-fadeIn">{errors.currentPassword}</p>}
                                        </div>
                                        <div className="space-y-2">
                                            <label className={`block text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Nova Senha</label>
                                            <input type="password" value={formData.newPassword} onChange={(e) => handleInputChange('newPassword', e.target.value)} disabled={isLoading}
                                                className={`${inputBase} ${errors.newPassword ? inputError : ''}`} placeholder="Mínimo 8 caracteres" />
                                            {errors.newPassword && <p className="text-sm font-medium text-red-500 animate-fadeIn">{errors.newPassword}</p>}
                                            {formData.newPassword && <div className="mt-2"><PasswordStrengthIndicator password={formData.newPassword} darkMode={darkMode} /></div>}
                                        </div>
                                        <div className="space-y-2">
                                            <label className={`block text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Confirmar Nova Senha</label>
                                            <input type="password" value={formData.confirmPassword} onChange={(e) => handleInputChange('confirmPassword', e.target.value)} disabled={isLoading}
                                                className={`${inputBase} ${errors.confirmPassword ? inputError : ''}`} placeholder="Repita a nova senha" />
                                            {errors.confirmPassword && <p className="text-sm font-medium text-red-500 animate-fadeIn">{errors.confirmPassword}</p>}
                                        </div>
                                    </div>
                                )}
                            </div>

                            <div className={`flex flex-col sm:flex-row justify-end items-center gap-4 pt-6 mt-6 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                                <button type="button" onClick={handleCancel} disabled={isLoading}
                                    className={`w-full sm:w-auto px-6 py-3 rounded-xl font-bold transition-all ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}>
                                    Cancelar
                                </button>
                                <button type="submit" disabled={isLoading}
                                    className={`w-full sm:w-auto inline-flex items-center justify-center gap-2 px-8 py-3 rounded-xl font-bold transition-all transform hover:-translate-y-0.5 shadow-lg hover:shadow-xl ${darkMode ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:opacity-90' : 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:opacity-90'}`}>
                                    {isLoading ? (
                                        <>
                                            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                            Salvando...
                                        </>
                                    ) : (
                                        <>
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                                            Salvar Alterações
                                        </>
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>
                )}
            </div>
        </div>
    );
}

// Componente de Login e Cadastro
function LoginForm({ onLogin, darkMode }) {
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
            console.error('Erro no login:', error);
            setError(error.message || 'Usuário ou senha inválidos.');
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
        <div className="min-h-screen flex items-center justify-center p-4 transition-all duration-700 animate-fadeIn relative overflow-hidden"
            style={{
                backgroundImage: "url('image/fundo.jpg')",
                backgroundSize: 'cover',
                backgroundPosition: 'center',
                backgroundRepeat: 'no-repeat',
                perspective: '1200px'
            }}>
            {/* Overlay sutil para garantir legibilidade e profundidade */}
            <div className={`absolute inset-0 ${darkMode ? 'bg-black/40' : 'bg-blue-900/15'} backdrop-blur-[4px]`}></div>
            <div
                className={`relative max-w-md w-full p-8 card-modern glass ${darkMode ? 'dark border-blue-500/30 bg-gray-900/40 shadow-[0_50px_100px_-20px_rgba(0,0,0,0.6),0_30px_60px_-30px_rgba(0,0,0,0.7),inset_0_1px_1px_rgba(255,255,255,0.1)]' : 'bg-white/75 border-white/60 shadow-[0_40px_80px_-15px_rgba(0,0,0,0.3),inset_0_1px_1px_rgba(255,255,255,0.5)]'} animate-fadeInUp backdrop-blur-2xl rounded-[2.5rem]`}
                style={{
                    transform: 'rotateX(3deg) rotateY(-2deg) translateZ(30px)',
                    transformStyle: 'preserve-3d'
                }}
            >
                <div className="text-center mb-6">
                    <div className="relative inline-block mb-4 group transition-all duration-500 hover:scale-110">
                        {/* Glow de Fundo para efeito 'Pleno' */}
                        <div className={`absolute inset-0 blur-2xl rounded-full opacity-30 animate-pulse ${darkMode ? 'bg-blue-500' : 'bg-blue-400'}`}></div>
                        <img
                            src="image/ecossistema3.png"
                            alt="Logo Ecossistema DIAAF"
                            className="relative h-14 w-auto object-contain drop-shadow-2xl"
                        />
                    </div>
                    <h2
                        className={`text-xl font-black tracking-tighter ${darkMode ? 'text-white' : 'text-gray-900'} uppercase`}
                        style={{ fontFamily: "'Montserrat', sans-serif", letterSpacing: '-0.02em' }}
                    >
                        {isForgotPassword ? 'Recuperar Senha' : (isRegistering ? 'Criar Nova Conta' : 'Ecossistema DIAAF')}
                    </h2>
                    <p className={`mt-3 text-sm font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        {isForgotPassword ? 'Informe seu usuário para solicitar o desbloqueio' : (isRegistering ? 'Preencha os dados abaixo para se cadastrar' : 'Faça login para acessar o sistema')}
                    </p>
                </div>

                {isForgotPassword ? (
                    <form className="space-y-6 animate-fadeIn" onSubmit={handleForgotPasswordSubmit}>
                        <div className="space-y-2">
                            <label htmlFor="forgot-username" className={`block text-sm font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Nome de Usuário</label>
                            <input
                                id="forgot-username"
                                name="username"
                                type="text"
                                required
                                autoComplete="username"
                                className={`input-modern w-full ${darkMode ? 'dark' : ''}`}
                                placeholder="Seu nome de usuário cadastrado&hellip;"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                            />
                        </div>

                        {forgotPasswordMsg.text && (
                            <div className={`text-sm text-center p-4 rounded-xl border animate-fadeIn ${forgotPasswordMsg.type === 'success' ? (darkMode ? 'bg-green-900/30 border-green-700 text-green-300' : 'bg-green-50 border-green-200 text-green-700') : (darkMode ? 'bg-red-900/30 border-red-700 text-red-300' : 'bg-red-50 border-red-200 text-red-700')}`}>
                                <div className="flex items-center justify-center gap-2">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={forgotPasswordMsg.type === 'success' ? "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" : "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"} /></svg>
                                    <span className="font-semibold">{forgotPasswordMsg.text}</span>
                                </div>
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={isLoading}
                            className="btn-modern gradient-primary w-full py-3 text-white shadow-blue-500/25 disabled:opacity-50"
                        >
                            {isLoading ? 'Enviando Solicitação&hellip;' : 'Solicitar Redefinição'}
                        </button>

                        <div className="text-center pt-4 border-t border-gray-100 dark:border-gray-700/50">
                            <button
                                type="button"
                                onClick={toggleForgotPassword}
                                className={`text-sm font-bold transition-all hover:opacity-80 scale-100 hover:scale-105 active:scale-95 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}
                            >
                                Voltar para o Login Seguro
                            </button>
                        </div>
                    </form>
                ) : (
                    <form className="space-y-5 animate-fadeIn" onSubmit={handleSubmit}>
                        <div className="space-y-4">
                            {isRegistering && (
                                <>
                                    <div className="space-y-2">
                                        <label htmlFor="reg-name" className={`block text-sm font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Nome Completo</label>
                                        <input
                                            id="reg-name"
                                            name="name"
                                            type="text"
                                            required
                                            autoComplete="name"
                                            className={`input-modern w-full ${darkMode ? 'dark' : ''}`}
                                            placeholder="Seu nome completo&hellip;"
                                            value={name}
                                            onChange={(e) => setName(e.target.value)}
                                        />
                                    </div>
                                    <div className="space-y-2">
                                        <label htmlFor="reg-email" className={`block text-sm font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Email</label>
                                        <input
                                            id="reg-email"
                                            name="email"
                                            type="email"
                                            required
                                            autoComplete="email"
                                            className={`input-modern w-full ${darkMode ? 'dark' : ''}`}
                                            placeholder="seu@email.com&hellip;"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                        />
                                    </div>
                                </>
                            )}

                            <div className="space-y-2">
                                <label htmlFor="login-username" className={`block text-sm font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Usuário</label>
                                <input
                                    id="login-username"
                                    name="username"
                                    type="text"
                                    required
                                    autoComplete="username"
                                    className={`input-modern w-full ${darkMode ? 'dark' : ''}`}
                                    placeholder="Nome de usuário&hellip;"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                />
                            </div>

                            <div className="space-y-2">
                                <label htmlFor="login-password" className={`block text-sm font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Senha</label>
                                <input
                                    id="login-password"
                                    name="password"
                                    type="password"
                                    required
                                    autoComplete={isRegistering ? "new-password" : "current-password"}
                                    className={`input-modern w-full ${darkMode ? 'dark' : ''}`}
                                    placeholder="Sua senha secreta&hellip;"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                />
                            </div>

                            {isRegistering && (
                                <div className="space-y-2">
                                    <label htmlFor="reg-confirm" className={`block text-sm font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Confirmar Senha</label>
                                    <input
                                        id="reg-confirm"
                                        name="confirmPassword"
                                        type="password"
                                        required
                                        autoComplete="new-password"
                                        className={`input-modern w-full ${darkMode ? 'dark' : ''}`}
                                        placeholder="Repita a nova senha&hellip;"
                                        value={confirmPassword}
                                        onChange={(e) => setConfirmPassword(e.target.value)}
                                    />
                                </div>
                            )}
                        </div>

                        {error && (
                            <div className={`p-4 rounded-xl border animate-pulse ${error.includes('bloqueada') || error.includes('Restam') ? (darkMode ? 'bg-amber-900/30 border-amber-700 text-amber-300' : 'bg-amber-50 border-amber-200 text-amber-800') : (darkMode ? 'bg-red-900/30 border-red-700 text-red-300' : 'bg-red-50 border-red-200 text-red-800')}`}>
                                <p className="text-sm font-semibold text-center">{error}</p>
                            </div>
                        )}

                        <div className="pt-2">
                            <button
                                type="submit"
                                disabled={isLoading}
                                className={`btn-modern w-full py-3.5 text-white text-base shadow-lg transition-all active:scale-95 disabled:opacity-50 ${isRegistering ? 'bg-gradient-to-r from-emerald-500 to-teal-600 shadow-emerald-500/25' : 'gradient-primary shadow-blue-500/25'}`}
                            >
                                {isLoading ? (
                                    <div className="flex items-center justify-center gap-2">
                                        <div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div>
                                        <span>Processando&hellip;</span>
                                    </div>
                                ) : (isRegistering ? 'Criar Minha Conta' : 'Acessar Sistema')}
                            </button>
                        </div>

                        <div className="flex flex-col gap-4 text-center pt-6 border-t border-gray-100 dark:border-gray-700/50">
                            {!isRegistering && (
                                <button
                                    id="forgot-password-link"
                                    type="button"
                                    onClick={toggleForgotPassword}
                                    className={`font-medium transition-colors hover:underline ${darkMode ? 'text-indigo-400 hover:text-indigo-300' : 'text-indigo-600 hover:text-indigo-700'}`}
                                >
                                    Esqueceu sua senha?
                                </button>
                            )}
                            <button
                                type="button"
                                onClick={toggleMode}
                                className={`font-medium transition-colors hover:underline ${isRegistering ? 'w-full text-center' : ''} ${darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'}`}
                            >
                                {isRegistering ? 'Voltar para o Login' : 'Criar nova conta'}
                            </button>
                        </div>
                    </form>
                )}
            </div>

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
function PasswordStrengthIndicator({ password, darkMode }) {
    const score = CredentialValidator.generatePasswordStrengthScore(password);
    const validation = CredentialValidator.validatePassword(password);

    const getStrengthText = (score) => {
        switch (score) {
            case 0:
            case 1: return 'Muito Fraca';
            case 2: return 'Fraca';
            case 3: return 'Média';
            case 4: return 'Forte';
            case 5: return 'Muito Forte';
            default: return 'Muito Fraca';
        }
    };

    const getStrengthColor = (score) => {
        switch (score) {
            case 0:
            case 1: return 'bg-red-500';
            case 2: return 'bg-orange-500';
            case 3: return 'bg-yellow-500';
            case 4: return 'bg-blue-500';
            case 5: return 'bg-green-500';
            default: return 'bg-gray-300';
        }
    };

    if (!password) return null;

    return (
        <div className="mt-2">
            <div className="flex items-center justify-between mb-1">
                <span className={`text-xs ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                    Força da senha:
                </span>
                <span className={`text-xs font-medium ${score <= 2 ? 'text-red-500' :
                    score <= 3 ? 'text-yellow-500' :
                        'text-green-500'
                    }`}>
                    {getStrengthText(score)}
                </span>
            </div>
            <div className={`w-full bg-gray-200 rounded-full h-2 ${darkMode ? 'bg-gray-700' : ''}`}>
                <div
                    className={`h-2 rounded-full transition-all duration-300 ${getStrengthColor(score)}`}
                    style={{ width: `${(score / 5) * 100}%` }}
                ></div>
            </div>
            {validation.errors.length > 0 && (
                <div className="mt-1">
                    {validation.errors.map((error, index) => (
                        <p key={index} className="text-xs text-red-500">
                            • {error}
                        </p>
                    ))}
                </div>
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
function AdminUsersTable({ darkMode, adminUsersListKey, onRefreshNeeded }) {
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

    if (isLoading) {
        return <div className={`p-4 text-center ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Carregando usuários...</div>;
    }

    return (
        <table className="min-w-full">
            <thead className={darkMode ? 'bg-gray-700' : 'bg-gray-100'}>
                <tr>
                    <th className={`px-4 py-3 text-left text-xs font-semibold uppercase ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Nome</th>
                    <th className={`px-4 py-3 text-left text-xs font-semibold uppercase ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Usuário</th>
                    <th className={`px-4 py-3 text-left text-xs font-semibold uppercase ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Perfil</th>
                    <th className={`px-4 py-3 text-left text-xs font-semibold uppercase ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Status</th>
                    <th className={`px-4 py-3 text-right text-xs font-semibold uppercase ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Ações</th>
                </tr>
            </thead>
            <tbody className={`divide-y ${darkMode ? 'divide-gray-700' : 'divide-gray-200'}`}>
                {users.map(user => {
                    // Trata boolean do SQLite ("true" / 1 ou "false" / 0)
                    const isBlocked = user.isBlockedByAdmin === true || user.isBlockedByAdmin === 1;

                    return (
                        <tr key={user.id} className={darkMode ? 'bg-gray-800' : 'bg-white'}>
                            <td className={`px-4 py-3 text-sm flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                <div className="w-6 h-6 rounded-full bg-blue-500 flex items-center justify-center text-white text-xs font-bold">
                                    {(user.name || '?').charAt(0).toUpperCase()}
                                </div>
                                {user.name}
                            </td>
                            <td className={`px-4 py-3 text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>{user.username}</td>
                            <td className="px-4 py-3">
                                <span className={`text-xs px-2 py-1 rounded-full ${user.role === 'admin' ? (darkMode ? 'bg-red-900/50 text-red-400' : 'bg-red-100 text-red-700') : (darkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-100 text-gray-700')}`}>
                                    {user.role === 'admin' ? 'Administrador' : 'Usuário'}
                                </span>
                            </td>
                            <td className="px-4 py-3">
                                <span className={`text-xs px-2 py-1 flex items-center gap-1 w-max rounded-full font-medium ${isBlocked ? (darkMode ? 'bg-red-900/40 text-red-400' : 'bg-red-100 text-red-600') : (darkMode ? 'bg-green-900/40 text-green-400' : 'bg-green-100 text-green-600')}`}>
                                    {isBlocked ? 'Bloqueado' : 'Ativo'}
                                </span>
                            </td>
                            <td className="px-4 py-3 text-right text-sm">
                                {user.role !== 'admin' && (
                                    <div className="flex justify-end gap-2">
                                        <button onClick={() => handleResetPassword(user)} className={`p-1.5 rounded-lg border flex items-center justify-center ${darkMode ? 'border-gray-600 hover:bg-gray-700 text-gray-300' : 'border-gray-200 hover:bg-gray-100 text-gray-600'}`} title="Resetar senha: 'Mudar@123'">
                                            🔑
                                        </button>
                                        <button onClick={() => handleToggleBlock(user)} className={`p-1.5 rounded-lg border flex items-center justify-center ${darkMode ? 'border-gray-600 hover:bg-gray-700 text-gray-300' : 'border-gray-200 hover:bg-gray-100 text-gray-600'}`} title={isBlocked ? 'Desbloquear usuário' : 'Bloquear usuário'}>
                                            🔒
                                        </button>
                                        <button onClick={() => handleDelete(user)} className={`p-1.5 rounded-lg border flex items-center justify-center ${darkMode ? 'border-red-900 hover:bg-red-900/50 text-red-400' : 'border-red-200 hover:bg-red-100 text-red-600'}`} title="Excluir">
                                            🗑️
                                        </button>
                                    </div>
                                )}
                            </td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}

// Componente Sidebar Completo com Menu Lateral
function Sidebar({ darkMode, currentView, setCurrentView, currentUser, onLogout, sidebarMobileOpen, onCloseSidebar }) {
    const [isExpanded, setIsExpanded] = useState(false);

    const handleNavigate = (view) => {
        setCurrentView(view);
        onCloseSidebar?.();
    };

    const menuItems = [
        {
            id: 'profile',
            label: 'Meu Perfil',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
            ),
            view: 'profile'
        },
        {
            id: 'other-services',
            label: 'Serviços Internos',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                </svg>
            ),
            view: 'other-services'
        }
    ];

    // Itens administrativos (apenas para admin)
    const adminItems = [
        {
            id: 'admin-dashboard',
            label: 'Auditoria',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            ),
            view: 'admin-dashboard'
        },
        {
            id: 'admin-users',
            label: 'Usuários',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                </svg>
            ),
            view: 'admin-users'
        },
        {
            id: 'admin-banners',
            label: 'Banners',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
                </svg>
            ),
            view: 'admin-banners'
        }
    ];

    const isActive = (id) => {
        return currentView === id;
    };

    return (
        <div
            className={`sidebar-container flex-shrink-0 transition-all duration-300 ease-in-out ${isExpanded ? 'w-64' : 'w-20'} 
                ${darkMode ? 'bg-gray-900 border-r border-gray-800' : 'bg-white border-r border-gray-200'} 
                flex flex-col h-full shadow-lg ${sidebarMobileOpen ? 'open' : ''}`}
            onMouseEnter={() => setIsExpanded(true)}
            onMouseLeave={() => setIsExpanded(false)}
        >
            {/* Logo/Header */}
            <div className={`p-4 border-b ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}>
                <div className="flex items-center gap-3">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0
                        ${darkMode ? 'bg-white shadow-[0_0_15px_rgba(59,130,246,0.5)]' : 'bg-white shadow-md'} 
                        overflow-hidden p-1.5 border ${darkMode ? 'border-blue-500' : 'border-gray-100'}`}>
                        <img src="image/ecossistema3.png" alt="DIAAF Logo" className="w-full h-full object-contain" />
                    </div>
                    {isExpanded && (
                        <div className="overflow-hidden animate-fadeInLeft">
                            <h1 className={`font-bold text-lg leading-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                Ecossistema DIAAF
                            </h1>
                            <p className={`text-[10px] uppercase tracking-tighter font-semibold ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                                Auditoria e Assuntos Fiscais
                            </p>
                        </div>
                    )}
                </div>
            </div>

            {/* Menu de Navegação */}
            <nav className="flex-1 py-4 overflow-y-auto custom-scrollbar">
                <div className="px-3 space-y-1">
                    {/* Separador Principal */}
                    {isExpanded && (
                        <p className={`px-3 text-xs font-semibold uppercase tracking-wider mb-2 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                            Menu Principal
                        </p>
                    )}

                    {/* Itens do Menu Principal */}
                    {menuItems.map((item) => (
                        <button
                            key={item.id}
                            onClick={() => handleNavigate(item.view)}
                            className={`w-full flex items-center gap-3 px-3 py-3 rounded-xl transition-all duration-200 group
                                ${isActive(item.id)
                                    ? `${darkMode ? 'bg-blue-600/20 text-blue-400' : 'bg-blue-50 text-blue-600'} shadow-sm`
                                    : `${darkMode ? 'text-gray-400 hover:bg-gray-800 hover:text-white' : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'}`
                                }`}
                            title={!isExpanded ? item.label : ''}
                        >
                            <div className={`flex-shrink-0 ${isActive(item.id) ? 'scale-110' : 'group-hover:scale-110'} transition-transform`}>
                                {item.icon}
                            </div>
                            {isExpanded && (
                                <span className="font-medium truncate animate-fadeInLeft">{item.label}</span>
                            )}
                            {isActive(item.id) && isExpanded && (
                                <div className={`ml-auto w-2 h-2 rounded-full ${darkMode ? 'bg-blue-400' : 'bg-blue-600'} animate-pulse`}></div>
                            )}
                        </button>
                    ))}

                    {/* Seção Administrativa (apenas para admin) */}
                    {currentUser?.role === 'admin' && (
                        <>
                            {isExpanded && (
                                <p className={`px-3 text-xs font-semibold uppercase tracking-wider mt-6 mb-2 ${darkMode ? 'text-red-400' : 'text-red-500'}`}>
                                    Administração
                                </p>
                            )}

                            {/* Separador visual */}
                            <div className={`my-2 border-t ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}></div>

                            {adminItems.map((item) => (
                                <button
                                    key={item.id}
                                    onClick={() => handleNavigate(item.view)}
                                    className={`w-full flex items-center gap-3 px-3 py-3 rounded-xl transition-all duration-200 group
                                        ${isActive(item.id)
                                            ? `${darkMode ? 'bg-red-600/20 text-red-400' : 'bg-red-50 text-red-600'} shadow-sm`
                                            : `${darkMode ? 'text-gray-400 hover:bg-gray-800 hover:text-red-400' : 'text-gray-600 hover:bg-red-50 hover:text-red-600'}`
                                        }`}
                                    title={!isExpanded ? item.label : ''}
                                >
                                    <div className={`flex-shrink-0 ${isActive(item.id) ? 'scale-110' : 'group-hover:scale-110'} transition-transform`}>
                                        {item.icon}
                                    </div>
                                    {isExpanded && (
                                        <span className="font-medium truncate animate-fadeInLeft">{item.label}</span>
                                    )}
                                    {isActive(item.id) && isExpanded && (
                                        <div className={`ml-auto w-2 h-2 rounded-full ${darkMode ? 'bg-red-400' : 'bg-red-600'} animate-pulse`}></div>
                                    )}
                                </button>
                            ))}
                        </>
                    )}
                </div>
            </nav>

            {/* Informações do Usuário no Rodapé */}
            <div className={`p-4 border-t ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}>
                <div className={`flex items-center gap-3 p-2 rounded-xl ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0
                        ${currentUser?.role === 'admin' ? 'bg-red-500' : 'bg-blue-500'} text-white font-bold shadow-md`}>
                        {currentUser?.name?.charAt(0).toUpperCase() || 'U'}
                    </div>
                    {isExpanded && (
                        <div className="overflow-hidden flex-1 min-w-0">
                            <p className={`font-semibold text-sm truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                {currentUser?.name || 'Usuário'}
                            </p>
                            <p className={`text-xs truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                {currentUser?.role === 'admin' ? 'Administrador' : 'Usuário'}
                            </p>
                        </div>
                    )}
                    {isExpanded && (
                        <button
                            onClick={onLogout}
                            className={`p-2 rounded-lg transition-all duration-200 ${darkMode ? 'hover:bg-gray-700 text-gray-400 hover:text-red-400' : 'hover:bg-gray-200 text-gray-500 hover:text-red-500'}`}
                            title="Sair"
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                            </svg>
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}

// ==================== PAINEL DE CONTROLE DE BANNERS ====================
// Config estática dos banners (UI, cores, links)
const BANNER_STATIC = {
    'iss-cnae': {
        label: 'Consultas Fiscais',
        menu: 'home',
        description: 'Acesse os serviços de consulta fiscal',
        icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
        light: 'from-blue-50 to-purple-50 border-blue-400 hover:border-blue-500',
        dark: 'from-blue-900/50 to-purple-900/50 border-blue-500/30 hover:border-blue-500',
        iconLight: 'bg-white text-blue-600 shadow-md',
        iconDark: 'bg-blue-500/20 text-blue-400',
        hoverBg: { light: 'bg-blue-600', dark: 'bg-white' },
        isModal: true,
        modalId: 'consultas-fiscais'
    },
    'pareceres': {
        label: 'Gerador de Pareceres',
        menu: 'home',
        description: 'Gere pareceres fiscais automaticamente',
        icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        href: 'https://opinion-factory-production.up.railway.app/',
        light: 'from-emerald-50 to-teal-50 border-emerald-400 hover:border-emerald-500',
        dark: 'from-emerald-900/50 to-teal-900/50 border-emerald-500/30 hover:border-emerald-500',
        iconLight: 'bg-white text-emerald-600 shadow-md',
        iconDark: 'bg-emerald-500/20 text-emerald-400',
        hoverBg: { light: 'bg-emerald-600', dark: 'bg-white' }
    },
    'incidencia': {
        label: 'Incidência do ISS',
        menu: 'home',
        description: 'LC 116/2003 – Art. 3º',
        icon: 'M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0zM15 11a3 3 0 11-6 0 3 3 0 016 0z',
        href: 'https://script.google.com/macros/s/AKfycbwFWD5zweoKS-WccLZJkH4KCVQSKcLR-guuITNhmOYg/dev',
        light: 'from-orange-50 to-amber-50 border-orange-400 hover:border-orange-500',
        dark: 'from-orange-900/50 to-amber-900/50 border-orange-500/30 hover:border-orange-500',
        iconLight: 'bg-white text-orange-600 shadow-md',
        iconDark: 'bg-orange-500/20 text-orange-400',
        hoverBg: { light: 'bg-orange-600', dark: 'bg-white' }
    },
    'processos': {
        label: 'Análise de Processos',
        menu: 'home',
        description: 'Visualize e analise processos fiscais',
        icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        href: 'https://reportterra-diaaf.up.railway.app/login',
        light: 'from-violet-50 to-indigo-50 border-violet-400 hover:border-violet-500',
        dark: 'from-violet-900/50 to-indigo-900/50 border-violet-500/30 hover:border-violet-500',
        iconLight: 'bg-white text-violet-600 shadow-md',
        iconDark: 'bg-violet-500/20 text-violet-400',
        hoverBg: { light: 'bg-violet-600', dark: 'bg-white' }
    },
    'nfse-nacional': {
        label: 'Gestão da NFS-e',
        menu: 'home',
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
        description: 'Publicações do Diário Oficial de Imperatriz',
        imageIcon: 'image/brasao.png',
        imageClass: 'w-full h-full object-cover rounded-full',
        href: 'https://diariooficial.imperatriz.ma.gov.br/publicacoes',
        light: 'from-slate-50 to-gray-50 border-slate-400 hover:border-slate-500',
        dark: 'from-slate-900/50 to-gray-900/50 border-slate-500/30 hover:border-slate-500',
        iconLight: 'bg-white text-slate-600 shadow-md',
        iconDark: 'bg-slate-500/20 text-slate-400',
        hoverBg: { light: 'bg-slate-600', dark: 'bg-white' }
    },
    'dte': {
        label: 'Prefeitura Moderna',
        menu: 'home',
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
        description: 'Painel gerencial de indicadores tributários',
        icon: 'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
        href: 'https://lookerstudio.google.com/u/0/reporting/c62bd011-53f8-4195-8770-cd7e617aa0ac/page/RT8lD',
        light: 'from-green-50 to-lime-50 border-green-200 hover:border-green-400',
        dark: 'from-green-900/50 to-lime-900/50 border-green-500/30 hover:border-green-500',
        iconLight: 'bg-white text-green-600 shadow-md',
        iconDark: 'bg-green-500/20 text-green-400',
        hoverBg: { light: 'bg-green-600', dark: 'bg-white' }
    },
    'entes': {
        label: 'Entes Federados',
        menu: 'home',
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
        description: 'Acesso via INTRANET sefazgo',
        href: 'http://192.168.201.198/menu',
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
    },
    // --- Sub-Banners Consultas Fiscais ---
    'consultas-iss-cnae': {
        label: 'Consulta ISS / CNAE',
        menu: 'consultas-sub',
        description: 'Pesquise alíquotas e códigos de serviço rapidamente',
        isInternal: true,
        view: 'search',
        icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
        light: 'from-blue-50 to-indigo-50 border-blue-400 hover:border-blue-500', dark: 'from-blue-900/40 to-indigo-900/40 border-blue-500/30 hover:border-blue-400', iconLight: 'bg-blue-100 text-blue-600', iconDark: 'bg-blue-500/20 text-blue-400'
    },
    'consultas-nfse-nacional': {
        label: 'Consulta NFS-e Nacional',
        menu: 'consultas-sub',
        description: 'Consulta Pública de NFS-e (Nota Fiscal de Serviços Eletrônica)',
        isInternal: false,
        href: 'https://www.nfse.gov.br/consultapublica',
        icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
        light: 'from-cyan-50 to-sky-50 border-cyan-400 hover:border-cyan-500', dark: 'from-cyan-900/40 to-sky-900/40 border-cyan-500/30 hover:border-cyan-400', iconLight: 'bg-cyan-100 text-cyan-600', iconDark: 'bg-cyan-500/20 text-cyan-400'
    }
};

// ==================== LISTAS AUXILIARES DE SUB-BANNERS ====================
const DTE_SUB_BANNERS_KEYS = [
    'dte-portal', 'dte-meuiss', 'dte-nfe', 'dte-iptu', 'dte-meuiptu', 'dte-login', 'dte-simples-fiscal', 'dte-helpdesk'
];

const CONSULTAS_FISCAIS_SUB_BANNERS_KEYS = [
    'consultas-iss-cnae', 'consultas-nfse-nacional'
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
            const merged = [...data];

            allKeys.forEach(key => {
                if (!merged.find(b => b.key === key)) {
                    const mapped = BANNER_STATIC[key];
                    if (['home', 'dte-sub', 'consultas-sub', 'outros'].includes(mapped.menu)) {
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

            const menuOrder = { 'home': 1, 'outros': 2, 'dte-sub': 3, 'consultas-sub': 4 };
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

    return ReactDOM.createPortal(
        <div
            className="fixed inset-0 overflow-y-auto"
            style={{ backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 9999 }}
            onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
        >
            <div className="flex items-center justify-center min-h-full p-6">
                <div className={`relative w-full max-w-md flex flex-col rounded-2xl shadow-2xl ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-white border border-gray-100'}`} style={{ maxHeight: '70vh' }} onClick={(e) => e.stopPropagation()}>
                    {/* Header */}
                    <div className={`flex items-center justify-between p-5 border-b ${darkMode ? 'border-gray-700' : 'border-gray-100'}`}>
                        <div>
                            <h3 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                🎛️ Banners de <span className={darkMode ? 'text-blue-400' : 'text-blue-600'}>{userName}</span>
                            </h3>
                            <p className={`text-xs mt-0.5 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                {hasAnyOverride ? 'Configuração personalizada ativa' : 'Seguindo padrão global'}
                            </p>
                        </div>
                        <button
                            onClick={onClose}
                            className={`p-2 rounded-lg transition-all ${darkMode ? 'hover:bg-gray-800 text-gray-400 hover:text-white' : 'hover:bg-gray-100 text-gray-500 hover:text-gray-800'}`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>

                    {/* Toast */}
                    {toast && (
                        <div className={`mx-5 mt-4 px-4 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2 ${toast.type === 'success' ? (darkMode ? 'bg-green-900/40 text-green-300 border border-green-700' : 'bg-green-50 text-green-800 border border-green-200') : (darkMode ? 'bg-red-900/40 text-red-300 border border-red-700' : 'bg-red-50 text-red-800 border border-red-200')}`}>
                            {toast.type === 'success' ? '✅' : '❌'} {toast.msg}
                        </div>
                    )}

                    {/* Lista de banners */}
                    <div className="flex-1 overflow-y-auto p-5 custom-scrollbar">
                        {loading ? (
                            <div className="flex justify-center items-center py-12">
                                <div className="animate-spin rounded-full h-8 w-8 border-4 border-blue-200 border-t-blue-600"></div>
                            </div>
                        ) : (
                            <div className="flex flex-col gap-2">
                                {banners.map((banner, index) => {
                                    const s = BANNER_STATIC[banner.key];
                                    if (!s) return null;
                                    const isSaving = savingId === banner.id;

                                    const prevS = index > 0 ? BANNER_STATIC[banners[index - 1].key] : null;
                                    const isNewGroup = !prevS || s.menu !== prevS.menu;

                                    const groupTitles = {
                                        'home': 'Banners Principais',
                                        'outros': 'Serviços Adicionais',
                                        'dte-sub': 'Sub-itens: Prefeitura Moderna',
                                        'consultas-sub': 'Sub-itens: Consultas Fiscais'
                                    };

                                    return (
                                        <React.Fragment key={banner.id}>
                                            {isNewGroup && (
                                                <div className={`text-[10px] font-bold uppercase tracking-widest mt-4 mb-2 px-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                    {groupTitles[s.menu] || 'Geral'}
                                                </div>
                                            )}
                                            <div
                                                draggable
                                                onDragStart={() => dragItem.current = index}
                                                onDragEnter={() => dragOverItem.current = index}
                                                onDragEnd={handleSort}
                                                onDragOver={e => e.preventDefault()}
                                                className={`flex items-center p-3.5 rounded-xl border transition-all duration-200 cursor-move ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100 shadow-sm hover:shadow-md'} ${!banner.enabled ? 'opacity-60' : ''}`}
                                            >
                                                <div className="text-gray-400 px-1.5 mr-1 cursor-grab">
                                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8h16M4 16h16" /></svg>
                                                </div>

                                                <div className={`w-10 h-10 rounded-full flex-shrink-0 flex items-center justify-center mr-3 ${darkMode ? s.iconDark : s.iconLight} overflow-hidden shadow-inner pointer-events-none`}>
                                                    {s.imageIcon ? (
                                                        <img src={s.imageIcon} alt="" className={s.imageClass || 'w-full h-full object-contain p-1.5'} />
                                                    ) : (
                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={s.icon || 'M4 5h16'} />
                                                        </svg>
                                                    )}
                                                </div>

                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <span className={`font-semibold text-sm truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{s.label || banner.label}</span>
                                                    </div>
                                                    <p className={`text-[10px] mt-0.5 ${banner.enabled ? (darkMode ? 'text-green-400' : 'text-green-600') : (darkMode ? 'text-gray-500' : 'text-gray-400')}`}>
                                                        {banner.enabled ? '● Visível' : '● Oculto'}
                                                    </p>
                                                </div>

                                                <button
                                                    onClick={() => handleToggle(banner)}
                                                    disabled={isSaving}
                                                    className={`relative flex-shrink-0 ml-3 inline-flex h-6 w-11 items-center rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 ${banner.enabled ? 'bg-blue-600' : (darkMode ? 'bg-gray-600' : 'bg-gray-200')} ${isSaving ? 'opacity-50 cursor-wait' : 'cursor-pointer'}`}
                                                >
                                                    <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition duration-200 ease-in-out flex items-center justify-center ${banner.enabled ? 'translate-x-5' : 'translate-x-0'}`}>
                                                        {isSaving && <div className="w-3 h-3 border-2 border-gray-300 border-t-gray-600 rounded-full animate-spin"></div>}
                                                    </span>
                                                </button>
                                            </div>
                                        </React.Fragment>
                                    );
                                })}
                            </div>
                        )}
                    </div>

                    <div className={`p-4 border-t text-center ${darkMode ? 'border-gray-700' : 'border-gray-100'}`}>
                        <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                            Arraste para reordenar
                        </p>
                    </div>
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

    return (
        <div className="animate-fadeInUp">
            {/* Modal de banners por usuário */}
            {selectedUserModal && (
                <AdminUserBannersModal
                    userId={selectedUserModal.id}
                    userName={selectedUserModal.name}
                    darkMode={darkMode}
                    onClose={() => setSelectedUserModal(null)}
                />
            )}

            {/* Header */}
            <div className={`mb-6 p-5 rounded-2xl ${darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-100 shadow-sm'}`}>
                <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-blue-900/30 text-blue-400' : 'bg-blue-50 text-blue-600'}`}>
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                        </svg>
                    </div>
                    <div>
                        <h2 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Gerenciador de Banners</h2>
                        <p className={`text-sm mt-0.5 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Personalize a visibilidade dos banners para cada usuário.</p>
                    </div>
                </div>
            </div>

            {/* Toast */}
            {toast && (
                <div className={`mb-6 px-4 py-3 rounded-xl text-sm font-medium flex items-center gap-2 animate-fadeInDown ${toast.type === 'success'
                    ? (darkMode ? 'bg-green-900/40 text-green-300 border border-green-700' : 'bg-green-50 text-green-800 border border-green-200')
                    : (darkMode ? 'bg-red-900/40 text-red-300 border border-red-700' : 'bg-red-50 text-red-800 border border-red-200')
                    }`}>
                    {toast.type === 'success' ? '✅' : '❌'} {toast.msg}
                </div>
            )}

            {/* Titulo Usuários */}
            <h3 className={`font-bold mb-4 ${darkMode ? 'text-white' : 'text-gray-800'}`}>Personalização de Usuários</h3>

            {/* Lista de Usuários */}
            {loadingUsers ? (
                <div className="flex justify-center items-center py-16">
                    <div className="animate-spin rounded-full h-8 w-8 border-4 border-blue-200 border-t-blue-600"></div>
                </div>
            ) : users.length === 0 ? (
                <div className={`flex flex-col items-center justify-center py-16 gap-3 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                    <svg className="w-12 h-12 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                    <p className="text-sm font-medium">Nenhum usuário autorizado encontrado.</p>
                </div>
            ) : (
                <div className="flex flex-col gap-3">
                    <div className={`px-4 py-3 rounded-xl text-sm flex items-start gap-2 ${darkMode ? 'bg-blue-900/20 text-blue-300 border border-blue-700/30' : 'bg-blue-50 text-blue-800 border border-blue-200'}`}>
                        💡 <span>Clique em <strong>Gerenciar Banners</strong> para personalizar a visibilidade de cada banner por usuário.</span>
                    </div>
                    {users.map(user => (
                        <div
                            key={user.id}
                            className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${darkMode ? 'bg-gray-800 border-gray-700 hover:border-gray-600' : 'bg-white border-gray-100 shadow-sm hover:shadow-md'}`}
                        >
                            <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 font-bold text-white text-base shadow-md ${darkMode ? 'bg-blue-700' : 'bg-blue-500'}`}>
                                {(user.name || user.username)?.charAt(0).toUpperCase()}
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className={`font-semibold truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{user.name || user.username}</p>
                                <p className={`text-xs truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>@{user.username}</p>
                            </div>
                            <button
                                onClick={() => setSelectedUserModal({ id: user.id, name: user.name || user.username })}
                                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 flex-shrink-0 ${darkMode ? 'bg-blue-600/20 text-blue-400 hover:bg-blue-600/40 border border-blue-600/30' : 'bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200'}`}
                            >
                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                                </svg>
                                Gerenciar Banners
                            </button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
// ========================================================================

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
                const validUser = await ApiService.validateSession();
                if (validUser) {
                    setCurrentUser(validUser);
                } else {
                    setIsAuthenticated(false);
                    setCurrentUser(null);
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
    const [filteredData, setFilteredData] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [darkMode, setDarkMode] = useState(() => {
        const saved = localStorage.getItem('darkMode');
        return saved ? JSON.parse(saved) : false;
    });
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [modalResults, setModalResults] = useState([]);
    const [noResults, setNoResults] = useState(false);



    // Estado da Tela de Bloqueio por inatividade
    const [isLockedOut, setIsLockedOut] = useState(() => {
        return localStorage.getItem('isLockedOut') === 'true';
    });
    const [unlockPassword, setUnlockPassword] = useState('');
    const [unlockError, setUnlockError] = useState('');
    const [isUnlocking, setIsUnlocking] = useState(false);
    const [wakeProgress, setWakeProgress] = useState(0); // 0 a 100
    const inactivityTimeoutRef = useRef(null);

    // Estado para usuários pendentes (apenas admin)
    const [pendingUsers, setPendingUsers] = useState([]);
    // Força re-render da lista de usuários na view admin após bloqueio/delete/reset
    const [adminUsersListKey, setAdminUsersListKey] = useState(0);
    const [auditUserFilter, setAuditUserFilter] = useState('');
    const [auditTypeFilter, setAuditTypeFilter] = useState(''); // 'banner', 'login_failure', etc.
    const [dteModalOpen, setDteModalOpen] = useState(false);
    const [consultasModalOpen, setConsultasModalOpen] = useState(false);
    const [bibliotecaModalOpen, setBibliotecaModalOpen] = useState(false);
    const [bibliotecaCategoria, setBibliotecaCategoria] = useState(null);
    const [bibliotecaSearch, setBibliotecaSearch] = useState('');
    const [expandedBanner, setExpandedBanner] = useState(null); // ID do banner atualmente expandido (accordion)

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
    const [bannerConfig, setBannerConfig] = useState([]);

    // Drag and Drop Banners refs
    const dragItem = useRef();
    const dragOverItem = useRef();
    const [isReorderingBanners, setIsReorderingBanners] = useState(false);
    const [isDraggingBanners, setIsDraggingBanners] = useState(false); // New state for global CSS

    const [freezeModalBanner, setFreezeModalBanner] = useState(null);

    // Carregar/recarregar config de banners ao montar e sempre que voltar para Home
    useEffect(() => {
        const defaultBanners = [
            { id: 'banner-iss-cnae', key: 'iss-cnae', label: 'Consulta ISS / CNAE', enabled: true },
            { id: 'banner-pareceres', key: 'pareceres', label: 'Gerador de Pareceres', enabled: true },
            { id: 'banner-incidencia', key: 'incidencia', label: 'Incidência do ISS', enabled: true },
            { id: 'banner-processos', key: 'processos', label: 'Análise de Processos', enabled: true },
            { id: 'banner-entes', key: 'entes', label: 'Entes Federados', enabled: true },
            { id: 'banner-empresa-facil', key: 'empresa-facil', label: 'Empresa Fácil', enabled: true },
            { id: 'banner-biblioteca', key: 'biblioteca', label: 'Biblioteca', enabled: true },
            { id: 'banner-sistema-ponto', key: 'sistema-ponto', label: 'Sistema de Ponto', enabled: true },
            { id: 'banner-justificativas-ponto', key: 'justificativas-ponto', label: 'Justificativas de Ponto', enabled: true },
            { id: 'banner-contra-cheque', key: 'contra-cheque', label: 'Contra-cheque', enabled: true },
            // Sub-Banners DTE
            { id: 'dte-portal', key: 'dte-portal', label: 'Terra Cloud (DTE)', enabled: true },
            { id: 'dte-meuiss', key: 'dte-meuiss', label: 'Meu ISS (DTE)', enabled: true },
            { id: 'dte-nfe', key: 'dte-nfe', label: 'NFS-e / Nota Fiscal (DTE)', enabled: true },
            { id: 'dte-iptu', key: 'dte-iptu', label: 'Protocolo (DTE)', enabled: true },
            { id: 'dte-meuiptu', key: 'dte-meuiptu', label: 'Meu IPTU (DTE)', enabled: true },
            { id: 'dte-login', key: 'dte-login', label: 'DTE - Domicílio Tributário', enabled: true },
            { id: 'dte-simples-fiscal', key: 'dte-simples-fiscal', label: 'Simples Fiscal (DTE)', enabled: true },
            { id: 'dte-helpdesk', key: 'dte-helpdesk', label: 'HelpDesk Tickets (DTE)', enabled: true },
            // Sub-Banners Consultas Fiscais
            { id: 'consultas-iss-cnae', key: 'consultas-iss-cnae', label: 'Consulta ISS / CNAE (CF)', enabled: true },
            { id: 'consultas-nfse-nacional', key: 'consultas-nfse-nacional', label: 'Consulta NFS-e Nacional (CF)', enabled: true },
        ];

        const loadBanners = () => {
            // Passa o token para receber banners personalizados do usuário
            ApiService.getBanners()
                .then(data => {
                    // Mescla banners da API com os defaults para garantir que novos banners apareçam
                    // mesmo se o backend estiver desatualizado (sem restart)
                    const merged = [...data];
                    defaultBanners.forEach(def => {
                        if (!merged.find(b => b.key === def.key)) {
                            merged.push(def);
                        }
                    });
                    setBannerConfig(merged);
                })
                .catch(() => {
                    setBannerConfig(defaultBanners);
                });
        };
        loadBanners();
    }, [currentView, isAuthenticated]);

    // Função para recarregar banners manualmente (ex: após gerenciar banners de um usuário)
    const reloadBanners = () => {
        ApiService.getBanners()
            .then(data => setBannerConfig(data))
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
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('currentUser', JSON.stringify(user));

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

    // ----- LOGICA DE INATIVIDADE (5 MINUTOS) -----
    const resetInactivityTimer = () => {
        if (!isAuthenticated || isLockedOut) return;

        if (inactivityTimeoutRef.current) {
            clearTimeout(inactivityTimeoutRef.current);
        }

        // 300000 ms = 5 minutos
        inactivityTimeoutRef.current = setTimeout(() => {
            setIsLockedOut(true);
            localStorage.setItem('isLockedOut', 'true');
        }, 300000);
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
    }, [isAuthenticated, isLockedOut]);

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
                const maxRetries = 15;
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
                        if (retryCount < maxRetries) { // maxRetries * 2s = 30s
                            setTimeout(retryLogin, 2000);
                        } else {
                            setWakeProgress(0);
                            setUnlockError('Servidor não respondeu a tempo. Atualize a página e tente novamente.');
                            setIsUnlocking(false);
                        }
                    }
                };
                setTimeout(retryLogin, 2000);
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
    }, []);

    // Função para normalizar texto (remove espaços extras e converte para minúsculo)
    const normalizeText = (text) => {
        if (!text) return '';
        return text.toString().trim().toLowerCase();
    };

    // Função para normalizar códigos removendo zeros à esquerda
    const normalizeCode = (code) => {
        if (!code) return '';
        const cleanCode = code.toString().trim();

        // Se contém pontos, normaliza cada parte separadamente
        if (cleanCode.includes('.')) {
            return cleanCode.split('.').map(part => {
                // Remove zeros à esquerda de cada parte, mas mantém pelo menos um dígito
                return part.replace(/^0+/, '') || '0';
            }).join('.');
        }

        // Se é só números, remove zeros à esquerda
        return cleanCode.replace(/^0+/, '') || '0';
    };

    // Função para verificar se é um código (números, pontos, hífens e barras)
    const isCode = (term) => {
        return /^[\d\-\/\.]+$/.test(term.trim());
    };

    // Função para normalizar códigos CNAE para busca flexível
    const normalizeCnaeCode = (code) => {
        if (!code) return '';
        // Remove espaços, hífens e barras, mantém apenas números
        return code.toString().replace(/[\s\-\/]/g, '').trim();
    };

    // Função de busca assertiva específica para cada tipo de campo
    const assertiveSearch = (field, term, fieldType = 'generic') => {
        if (!field || !term) return false;

        const normalizedField = normalizeText(field);
        const normalizedTerm = normalizeText(term);

        console.log(`Comparando: "${normalizedField}" com "${normalizedTerm}" (tipo: ${fieldType})`); // Debug

        // Se o termo é um código, aplica lógica específica por tipo de campo
        if (isCode(term)) {
            // Para códigos de item da lista (LIST LC) - busca mais restritiva
            if (fieldType === 'listlc') {
                const normalizedCodeTerm = normalizeCode(normalizedTerm);
                const fieldCodeMatch = normalizedField.match(/^([\d\.\-\/]+)/);

                if (fieldCodeMatch) {
                    const fieldCode = normalizeCode(fieldCodeMatch[1]);

                    // 1. Busca exata após normalização
                    if (fieldCode === normalizedCodeTerm) {
                        console.log(`Busca exata de LIST LC "${normalizedCodeTerm}" encontrada em "${fieldCode}": true`); // Debug
                        return true;
                    }

                    // 2. Busca parcial apenas se o termo termina com ponto (ex: "7." para buscar "7.01", "7.02", etc.)
                    if (normalizedTerm.endsWith('.') && fieldCode.startsWith(normalizedCodeTerm.slice(0, -1) + '.')) {
                        console.log(`Busca parcial de LIST LC "${normalizedCodeTerm}" encontrada em "${fieldCode}": true`); // Debug
                        return true;
                    }

                    // 3. Se não tem ponto no termo, busca apenas códigos que começam exatamente com o número seguido de ponto
                    if (!normalizedTerm.includes('.')) {
                        const exactPattern = new RegExp(`^${normalizedCodeTerm}\.`);
                        if (exactPattern.test(fieldCode)) {
                            console.log(`Busca de categoria LIST LC "${normalizedCodeTerm}" encontrada em "${fieldCode}": true`); // Debug
                            return true;
                        }
                    }
                }

                console.log(`Busca de LIST LC "${normalizedTerm}" em "${normalizedField}": false`); // Debug
                return false;
            }

            // Para códigos CNAE - mantém busca flexível
            if (fieldType === 'cnae') {
                const cleanTerm = normalizeCnaeCode(normalizedTerm);
                const cleanField = normalizeCnaeCode(normalizedField);

                // 1. Busca exata após normalização
                if (cleanField === cleanTerm) {
                    console.log(`Busca exata de CNAE "${cleanTerm}" encontrada em "${cleanField}": true`); // Debug
                    return true;
                }

                // 2. Busca por início do código (busca parcial)
                if (cleanField.startsWith(cleanTerm)) {
                    console.log(`Busca parcial de CNAE "${cleanTerm}" encontrada no início de "${cleanField}": true`); // Debug
                    return true;
                }

                console.log(`Busca de CNAE "${cleanTerm}" em "${cleanField}": false`); // Debug
                return false;
            }

            // Para outros códigos - busca genérica
            const normalizedCodeTerm = normalizeCode(normalizedTerm);
            const fieldCodeMatch = normalizedField.match(/^([\d\.\-\/]+)/);
            if (fieldCodeMatch) {
                const fieldCode = normalizeCode(fieldCodeMatch[1]);
                if (fieldCode === normalizedCodeTerm) {
                    console.log(`Busca exata de código "${normalizedCodeTerm}" encontrada em "${fieldCode}": true`); // Debug
                    return true;
                }
            }

            console.log(`Busca de código "${normalizedTerm}" em "${normalizedField}": false`); // Debug
            return false;
        } else {
            // Para descrições, busca por inclusão
            const result = normalizedField.includes(normalizedTerm);
            console.log(`Busca de descrição "${normalizedTerm}" em "${normalizedField}": ${result}`); // Debug
            return result;
        }
    };

    const filterData = () => {
        console.log('Iniciando filterData...'); // Debug
        console.log('Dados disponíveis:', data?.length || 0); // Debug

        if (!data || data.length === 0) {
            console.log('Nenhum dado disponível'); // Debug
            return [];
        }

        let filtered = data;

        if (searchTerm.trim()) {
            console.log('Filtrando por termo geral:', searchTerm); // Debug
            filtered = filtered.filter(item => {
                const match = assertiveSearch(item['LIST LC'], searchTerm, 'listlc') ||
                    assertiveSearch(item['Descrição item da lista da Lei Complementar nº 001/2003 - CTM'], searchTerm, 'description') ||
                    assertiveSearch(item['CNAE'], searchTerm, 'cnae') ||
                    assertiveSearch(item['Descrição do CNAE'], searchTerm, 'description');

                if (match) {
                    console.log('Item encontrado:', item['LIST LC']); // Debug
                }
                return match;
            });
        }

        console.log('Resultados filtrados:', filtered.length); // Debug
        return filtered;
    };



    const handleSearch = () => {
        setIsLoading(true);

        // Preparar dados da consulta para estatísticas
        const queryData = {
            searchTerm: searchTerm.trim()
        };

        const queryString = Object.values(queryData).filter(v => v).join(' | ');

        setTimeout(() => {
            const results = filterData();
            setModalResults(results);
            setNoResults(results.length === 0);
            setIsModalOpen(true);
            setIsLoading(false);

            // Registrar pesquisa nas estatísticas
            updateStatistics('search', {
                searchMode: 'combined',
                user: currentUser?.username || 'unknown',
                query: queryString || 'consulta vazia',
                results: results.length
            });
        }, 500);
    };

    const handleSearchKeyDown = (e) => {
        if (e.key !== 'Enter' || e.nativeEvent?.isComposing || isLoading) return;
        e.preventDefault();
        handleSearch();
    };

    const closeModal = () => {
        setIsModalOpen(false);
        setModalResults([]);
        setNoResults(false);
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
        return <LoginForm onLogin={handleLogin} darkMode={darkMode} />;
    }

    return (
        <div className="flex h-screen overflow-hidden relative">



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
                darkMode={darkMode}
                currentView={currentView}
                setCurrentView={setCurrentView}
                currentUser={currentUser}
                onLogout={handleLogout}
                sidebarMobileOpen={sidebarMobileOpen}
                onCloseSidebar={() => setSidebarMobileOpen(false)}
            />
            {/* Overlay do menu lateral no mobile */}
            {sidebarMobileOpen && (
                <div
                    className="sidebar-overlay active md:hidden"
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

            <div className="flex-1 overflow-y-auto">
                <div className={`min-h-screen transition-all duration-500 ${darkMode ? 'bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900' : 'bg-gradient-to-br from-gray-100 via-gray-50 to-gray-100'}`}>
                    <div className="container mx-auto px-4 py-8 max-w-6xl">
                        <header className="mb-10 relative z-[20]">
                            {/* Header Desconstruída: Elementos nos cantos superiores */}
                            <div className="flex justify-between items-start pt-2 px-2 transition-all duration-500">

                                {/* Grupo Esquerdo: Menu Mobile e Perfil/Saudação */}
                                <div className="flex items-center gap-4 animate-fadeInLeft">
                                    <button
                                        type="button"
                                        onClick={() => setSidebarMobileOpen(true)}
                                        className={`sidebar-toggle-mobile md:hidden flex items-center justify-center p-3 rounded-2xl shadow-lg backdrop-blur-md transition-all active:scale-95 ${darkMode ? 'bg-gray-800/80 text-white' : 'bg-white/80 text-gray-700'}`}
                                        aria-label="Abrir menu"
                                    >
                                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                                        </svg>
                                    </button>

                                    {/* Botão Voltar ou Perfil */}
                                    {currentView !== 'home' ? (
                                        <button
                                            onClick={() => setCurrentView('home')}
                                            className={`glass-card-header flex items-center gap-2 px-5 py-3 rounded-2xl font-bold text-sm transition-all duration-300 hover:scale-105 active:scale-95 ${darkMode
                                                ? 'text-gray-200'
                                                : 'text-gray-700'
                                                } shadow-xl`}
                                        >
                                            <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                                            </svg>
                                            <span>Início</span>
                                        </button>
                                    ) : (
                                        currentUser && (
                                            <div className="flex items-center gap-3">
                                                {/* Seletor de Tema (Reposicionado como solicitado) */}
                                                <div className="glass-card-header flex items-center p-1.5 rounded-2xl shadow-xl">
                                                    <button
                                                        onClick={() => setDarkMode(!darkMode)}
                                                        className={`p-2.5 rounded-xl transition-all duration-300 active:scale-95 ${darkMode ? 'bg-blue-600/20 text-yellow-400 hover:bg-blue-600/30' : 'bg-blue-50 text-blue-600 hover:bg-blue-100'}`}
                                                        title={darkMode ? 'Modo Claro' : 'Modo Escuro'}
                                                    >
                                                        {darkMode ? (
                                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                                                            </svg>
                                                        ) : (
                                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                                                            </svg>
                                                        )}
                                                    </button>
                                                </div>

                                                <div className="glass-card-header flex items-center gap-4 px-5 py-3 rounded-2xl shadow-xl transition-all duration-300 hover:translate-y-[-2px]">
                                                    <div className="relative group">
                                                        <div className={`w-11 h-11 rounded-full flex items-center justify-center shadow-lg transform transition-all group-hover:scale-110 overflow-hidden ring-2 ${darkMode ? 'ring-blue-500/30' : 'ring-cyan-500/20'} bg-gradient-to-tr from-blue-600 to-cyan-600`}>
                                                            {(() => {
                                                                const firstName = (currentUser.name?.split(' ')[0] || currentUser.username || '').toLowerCase();
                                                                const femaleNames = ['maria', 'ana', 'julia', 'juliana', 'fernanda', 'patricia', 'aline', 'bruna', 'camila', 'jessica', 'amanda', 'leticia', 'beatriz', 'vanessa', 'mariana', 'gabriela', 'larissa', 'daniela', 'carla', 'renata'];
                                                                const isFemale = femaleNames.includes(firstName) || firstName.endsWith('a') || firstName.endsWith('e');
                                                                const avatarSrc = isFemale ? 'image/mulher.png' : 'image/homem.png';

                                                                return (
                                                                    <img
                                                                        src={avatarSrc}
                                                                        alt="Avatar"
                                                                        className="w-full h-full object-cover"
                                                                        onError={(e) => {
                                                                            e.target.style.display = 'none';
                                                                            e.target.nextSibling.style.display = 'block';
                                                                        }}
                                                                    />
                                                                );
                                                            })()}
                                                            <span className="text-white font-bold text-xs tracking-widest absolute" style={{ display: 'none' }}>
                                                                {currentUser?.name?.substring(0, 2).toUpperCase() || currentUser?.username.substring(0, 2).toUpperCase() || 'AD'}
                                                            </span>
                                                        </div>
                                                        <div className={`absolute bottom-0 right-0 w-3.5 h-3.5 rounded-full flex items-center justify-center border-2 border-white dark:border-gray-800 ${darkMode ? 'bg-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]' : 'bg-green-400'}`}>
                                                        </div>
                                                    </div>
                                                    <div className="hidden sm:block">
                                                        <h2 className={`font-bold text-base tracking-tight leading-none ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                            {currentUser.name?.split(' ')[0] || currentUser.username}
                                                        </h2>
                                                        <p className={`text-[10px] uppercase font-black tracking-widest mt-1.5 opacity-70 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                                                            {new Date().getHours() < 12 ? 'Bom dia' : new Date().getHours() < 18 ? 'Boa tarde' : 'Boa noite'}
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>
                                        )
                                    )}
                                </div>

                                {/* Grupo Direito: Controles (NextChat com Destaque) */}
                                <div className="flex items-center gap-3 animate-fadeInRight">
                                    {currentView === 'home' && (
                                        <div className="glass-card-header flex items-center gap-2 p-1 rounded-2xl shadow-xl">
                                            <div className="relative flex items-center gap-3">
                                                <a
                                                    href="https://chat.nextplan.tec.br/login"
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="relative group p-0.5 rounded-2xl transition-all duration-300 hover:scale-110 active:scale-95 ring-2 ring-blue-500/20 bg-blue-500/5 shadow-inner"
                                                    title="NextChat"
                                                >
                                                    <div className="w-12 h-12 overflow-hidden rounded-xl shadow-lg border-2 border-white/40 ring-4 ring-blue-400/10 animate-pulse-subtle bg-white flex items-center justify-center p-1">
                                                        <img
                                                            src="image/NextChat.png"
                                                            alt="NextChat"
                                                            className="w-full h-full object-contain"
                                                        />
                                                    </div>
                                                    {/* Badge de Destaque */}
                                                    <div className={`absolute top-0 -right-1 w-4 h-4 rounded-full border-2 border-white bg-blue-500 ${darkMode ? 'shadow-[0_0_10px_rgba(59,130,246,0.6)]' : ''}`}></div>

                                                    <div className="absolute top-[60px] right-0 whitespace-nowrap px-4 py-2 rounded-xl text-sm font-bold opacity-0 group-hover:opacity-100 transition-all duration-300 translate-y-2 group-hover:translate-y-0 pointer-events-none shadow-2xl bg-blue-600 text-white z-50">
                                                        <div className="absolute top-[-6px] right-4 w-0 h-0 border-l-[6px] border-r-[6px] border-b-[6px] border-transparent border-b-blue-600"></div>
                                                        Atendimento Virtual
                                                    </div>
                                                </a>

                                                {/* E-mail Institucional */}
                                                <a
                                                    href="https://mail.imperatriz.ma.gov.br/"
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="relative group p-0.5 rounded-2xl transition-all duration-300 hover:scale-110 active:scale-95 ring-2 ring-amber-500/20 bg-amber-500/5 shadow-inner"
                                                    title="E-mail Institucional"
                                                >
                                                    <div className={`w-12 h-12 overflow-hidden rounded-xl shadow-lg border-2 border-white/40 ring-4 ring-amber-400/10 transition-all ${darkMode ? 'bg-gray-800' : 'bg-white'} flex items-center justify-center`}>
                                                        <svg className={`w-7 h-7 ${darkMode ? 'text-amber-400' : 'text-amber-600'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                                        </svg>
                                                    </div>

                                                    {/* Badge de Destaque (Email) */}
                                                    <div className={`absolute top-0 -right-1 w-4 h-4 rounded-full border-2 border-white bg-amber-500 ${darkMode ? 'shadow-[0_0_10px_rgba(245,158,11,0.6)]' : ''}`}></div>

                                                    <div className="absolute top-[60px] right-0 whitespace-nowrap px-4 py-2 rounded-xl text-sm font-bold opacity-0 group-hover:opacity-100 transition-all duration-300 translate-y-2 group-hover:translate-y-0 pointer-events-none shadow-2xl bg-amber-600 text-white z-50">
                                                        <div className="absolute top-[-6px] right-4 w-0 h-0 border-l-[6px] border-r-[6px] border-b-[6px] border-transparent border-b-amber-600"></div>
                                                        E-mail Institucional
                                                    </div>
                                                </a>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Cabeçalho de Consulta Exclusivo da página Buscar */}
                            {currentView === 'search' && (
                                <div className="text-center animate-fadeInDown mt-10 mb-2">
                                    <h1 className={`text-4xl md:text-5xl font-extrabold mb-4 bg-gradient-to-r from-blue-600 via-cyan-500 to-indigo-600 bg-clip-text text-transparent`}>
                                        Consulta Lista/Cnae/Alíquota
                                    </h1>
                                    <p className={`text-lg md:text-xl mb-6 font-light ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                        Consulte itens da Lista de Serviços e suas respectivas alíquotas do ISS
                                    </p>
                                    <div className={`inline-flex items-center px-5 py-2.5 rounded-full text-sm font-medium shadow-sm transition-colors ${darkMode ? 'bg-gray-800/80 text-blue-300 border border-gray-700' : 'bg-white/80 text-blue-700 border border-blue-100'} backdrop-blur-sm`}>
                                        <div className="status-indicator status-active mr-2"></div>
                                        Sistema Online • {data.length} itens
                                        {currentUser?.role === 'admin' && (
                                            <span className="ml-3 px-2 py-0.5 bg-red-500/90 text-white text-[10px] uppercase font-bold tracking-wider rounded-md">
                                                Admin
                                            </span>
                                        )}
                                    </div>
                                </div>
                            )}
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

                        {currentView === 'home' && (
                            <div className="animate-fadeInUp space-y-4">
                                {/* Faixada Central de Serviços */}
                                <div className="text-center relative py-1 flex flex-col items-center">
                                    <div className={`absolute left-1/2 -translate-x-1/2 top-1/2 -translate-y-1/2 w-20 h-20 blur-3xl rounded-full opacity-20 ${darkMode ? 'bg-blue-500' : 'bg-blue-400'}`}></div>

                                    {/* Logo Branding Dashboard */}
                                    <div className="relative mb-1 animate-fadeInDown">
                                        <img
                                            src="image/ecossistema3.png"
                                            alt="EcoSistema Logo"
                                            className="h-14 md:h-16 w-auto object-contain drop-shadow-xl"
                                        />
                                    </div>

                                    <h2 className={`relative text-[9px] md:text-[10px] font-black tracking-[0.4em] uppercase mb-0.5 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                                        Central de Serviços
                                    </h2>
                                    <h1 className={`relative text-2xl md:text-3xl font-black tracking-tighter ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                        DIAAF
                                    </h1>
                                    <div className={`mt-2 mx-auto w-10 h-0.5 rounded-full ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}></div>
                                </div>

                                <div className={`grid gap-4 mt-1 ${bannerConfig.filter(b => (BANNER_STATIC[b.key]?.menu || 'home') === 'home' && (currentUser?.role === 'admin' || b.enabled)).length === 1 ? 'grid-cols-1 max-w-xs mx-auto' :
                                    bannerConfig.filter(b => (BANNER_STATIC[b.key]?.menu || 'home') === 'home' && (currentUser?.role === 'admin' || b.enabled)).length === 2 ? 'grid-cols-1 md:grid-cols-2' :
                                        'grid-cols-1 md:grid-cols-2 lg:grid-cols-3'
                                    }`}>
                                    {bannerConfig
                                        .filter(b => (BANNER_STATIC[b.key]?.menu || 'home') === 'home')
                                        .filter(b => currentUser?.role === 'admin' || b.enabled)
                                        .map((banner, index) => {
                                            const s = BANNER_STATIC[banner.key];
                                            if (!s) return null;
                                            const isAdmin = currentUser?.role === 'admin';
                                            const isDisabledForUser = !banner.enabled && !isAdmin;
                                            const isFrozen = banner.isFrozen === true;
                                            const isEffectivelyFrozen = isFrozen && !isAdmin;

                                            const cardClass = `flex flex-col items-center justify-center p-4 md:p-5 rounded-2xl border-2 transition-all transform hover:-translate-y-1 hover:shadow-2xl ${darkMode
                                                ? `bg-gradient-to-br ${s.dark}`
                                                : `bg-gradient-to-br ${s.light}`
                                                } group relative overflow-hidden ${isDisabledForUser ? 'opacity-40 cursor-default hover:translate-y-0 hover:shadow-none' : ''
                                                } ${(s.comingSoon || isEffectivelyFrozen) ? 'cursor-default hover:translate-y-0 hover:shadow-none opactity-75' : ''
                                                } ${(isAdmin || (isFrozen && isAdmin)) ? 'cursor-pointer active:cursor-grabbing' : ''}`;

                                            const content = (
                                                <>
                                                    {isAdmin && (
                                                        <div className="absolute top-3 right-3 z-20 flex items-center gap-2" onClick={e => e.stopPropagation()}>
                                                            <div className={`text-[9px] font-black uppercase tracking-tighter ${isFrozen ? (banner.freezeReason === 'construction' ? 'text-amber-500' : 'text-red-500 animate-pulse') : (darkMode ? 'text-green-400' : 'text-green-600')}`}>
                                                                {isFrozen ? (banner.freezeReason === 'construction' ? 'EM OBRAS' : 'REVISÃO') : 'ATIVO'}
                                                            </div>
                                                            <button
                                                                onClick={(e) => {
                                                                    e.preventDefault();
                                                                    e.stopPropagation();
                                                                    if (isFrozen) {
                                                                        handleFreezeToggleGlobal(banner);
                                                                    } else {
                                                                        setFreezeModalBanner(banner);
                                                                    }
                                                                }}
                                                                className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${isFrozen ? (banner.freezeReason === 'construction' ? 'bg-amber-500' : 'bg-red-500') : (darkMode ? 'bg-gray-700' : 'bg-gray-200')}`}
                                                                title={isFrozen ? "Descongelar serviço" : "Congelar serviço"}
                                                            >
                                                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${isFrozen ? 'translate-x-4' : 'translate-x-0'}`} />
                                                            </button>
                                                        </div>
                                                    )}
                                                    <div className={`absolute inset-0 opacity-0 ${'group-hover:opacity-10'} transition-opacity duration-300 ${darkMode ? s.hoverBg?.dark || 'bg-white' : s.hoverBg?.light || 'bg-blue-600'}`}></div>
                                                    <div className={`w-12 h-12 md:h-14 md:w-14 rounded-full flex items-center justify-center mb-3 ${darkMode ? s.iconDark : s.iconLight} shadow-inner pointer-events-none overflow-hidden`}>
                                                        {s.imageIcon ? (
                                                            <img src={s.imageIcon} alt="" className={s.imageClass || 'w-full h-full object-cover'} />
                                                        ) : (
                                                            <svg className="w-6 h-6 md:w-7 md:h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={s.icon} />
                                                            </svg>
                                                        )}
                                                    </div>
                                                    <h3 className={`text-lg md:text-xl font-bold mb-1 text-center pointer-events-none ${darkMode ? 'text-white' : 'text-gray-900'}`}>{s.label || banner.label}</h3>
                                                    {s.comingSoon && !isFrozen && (
                                                        <div className="flex justify-center mb-2">
                                                            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold pointer-events-none ${darkMode ? 'bg-amber-500/10 text-amber-400' : 'bg-amber-50 text-amber-700 font-bold'}`}>
                                                                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>
                                                                Em Construção
                                                            </span>
                                                        </div>
                                                    )}
                                                    {isFrozen && !isAdmin && (
                                                        <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-gray-900/10 dark:bg-black/30 backdrop-blur-[2px] rounded-3xl animate-fadeIn">
                                                            <div className={`px-4 py-2 rounded-xl shadow-lg border backdrop-blur-md flex items-center gap-2 ${banner.freezeReason === 'construction'
                                                                ? 'bg-amber-500/90 border-amber-400 text-white'
                                                                : 'bg-red-500/90 border-red-400 text-white'
                                                                }`}>
                                                                {banner.freezeReason === 'construction' ? (
                                                                    <svg className="w-5 h-5 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></svg>
                                                                ) : (
                                                                    <svg className="w-5 h-5 animate-spin-slow" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                                                                )}
                                                                <span className="font-bold text-sm tracking-wide">
                                                                    {banner.freezeReason === 'construction' ? 'EM CONSTRUÇÃO' : 'EM MANUTENÇÃO'}
                                                                </span>
                                                            </div>
                                                        </div>
                                                    )}
                                                    <p className={`text-[10px] md:text-xs text-center leading-relaxed pointer-events-none ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{s.description}</p>

                                                    {/* Contador de Sub-banners */}
                                                    {(() => {
                                                        let count = 0;
                                                        if (banner.key === 'dte') {
                                                            count = DTE_SUB_BANNERS_KEYS.filter(k => bannerConfig.find(bc => bc.key === k)?.enabled !== false).length;
                                                        } else if (banner.key === 'iss-cnae') {
                                                            count = CONSULTAS_FISCAIS_SUB_BANNERS_KEYS.filter(k => bannerConfig.find(bc => bc.key === k)?.enabled !== false).length;
                                                        }

                                                        if (count > 0) {
                                                            return (
                                                                <div className={`mt-2 px-2.5 py-1 rounded-lg text-[10px] font-bold flex items-center gap-1.5 transition-all duration-300 ${darkMode ? 'bg-white/10 text-white border border-white/10' : 'bg-gray-100 text-gray-700 border border-gray-200'}`}>
                                                                    <div className={`w-1.5 h-1.5 rounded-full animate-pulse ${darkMode ? 'bg-blue-400' : 'bg-blue-600'}`}></div>
                                                                    {count} {count === 1 ? 'serviço disponível' : 'serviços disponíveis'}
                                                                </div>
                                                            );
                                                        }
                                                        return null;
                                                    })()}
                                                    {isAdmin && (
                                                        <div className="absolute bottom-3 right-3 text-gray-400 opacity-0 group-hover:opacity-[0.8] transition-opacity cursor-grab active:cursor-grabbing pb-1 pr-1 pointer-events-none">
                                                            <svg className="w-6 h-6 drop-shadow-md" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8h16M4 16h16" /></svg>
                                                        </div>
                                                    )}
                                                </>
                                            );

                                            const dragProps = isAdmin ? {
                                                draggable: true,
                                                onDragStart: (e) => {
                                                    dragItem.current = index;
                                                    e.currentTarget.classList.add('opacity-50', 'scale-95');
                                                    setIsDraggingBanners(true); // Ativa injeção CSS global
                                                },
                                                onDragEnter: (e) => { dragOverItem.current = index; },
                                                onDragEnd: (e) => {
                                                    e.currentTarget.classList.remove('opacity-50', 'scale-95');
                                                    setIsDraggingBanners(false); // Desativa injeção CSS global
                                                    handleSortBanners();
                                                },
                                                onDragOver: (e) => e.preventDefault()
                                            } : {};

                                            if (s.isModal) {
                                                return (
                                                    <React.Fragment key={banner.id}>
                                                        <button
                                                            onClick={(e) => {
                                                                if (isEffectivelyFrozen) {
                                                                    e.preventDefault();
                                                                    const isConstruction = s.label.toLowerCase().includes('biblioteca') || s.description?.toLowerCase().includes('construção');
                                                                    const msg = isConstruction
                                                                        ? 'Este acesso está em desenvolvimento (EM CONSTRUÇÃO). Em breve disponível.'
                                                                        : 'Este acesso está temporariamente indisponível. Em manutenção.';
                                                                    alert(msg);
                                                                    return;
                                                                }
                                                                if (!isDisabledForUser) {
                                                                    // Toggle do Accordion
                                                                    if (expandedBanner === banner.id) {
                                                                        setExpandedBanner(null);
                                                                    } else {
                                                                        setExpandedBanner(banner.id);
                                                                        updateStatistics('bannerExpand', {
                                                                            bannerLabel: s.label || banner.label,
                                                                            user: currentUser ? currentUser.username : 'Visitante'
                                                                        });
                                                                    }
                                                                }
                                                            }}
                                                            disabled={isDisabledForUser}
                                                            className={cardClass}
                                                            {...dragProps}
                                                        >
                                                            {content}
                                                        </button>

                                                        {/* Accordion Content */}
                                                        {expandedBanner === banner.id && (
                                                            <div className="col-span-full animate-fadeInDown mt-2 mb-6">
                                                                <div className={`p-6 rounded-3xl border-2 ${darkMode ? 'bg-gray-800/40 border-gray-700/50' : 'bg-white border-gray-100'} shadow-xl backdrop-blur-sm relative overflow-hidden`}>
                                                                    {/* Header do Accordion */}
                                                                    <div className="flex items-center justify-between mb-6">
                                                                        <div className="flex items-center gap-3">
                                                                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${darkMode ? s.iconDark : s.iconLight}`}>
                                                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={s.icon} /></svg>
                                                                            </div>
                                                                            <div>
                                                                                <h4 className={`font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{s.label}</h4>
                                                                                <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Selecione o serviço desejado</p>
                                                                            </div>
                                                                        </div>
                                                                        <button onClick={() => setExpandedBanner(null)} className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-500'}`}>
                                                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                                                                        </button>
                                                                    </div>

                                                                    {/* Grid de Sub-banners */}
                                                                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                                                                        {(() => {
                                                                            let subKeys = [];
                                                                            if (s.modalId === 'dte') subKeys = DTE_SUB_BANNERS_KEYS;
                                                                            else if (s.modalId === 'consultas-fiscais') subKeys = CONSULTAS_FISCAIS_SUB_BANNERS_KEYS;

                                                                            if (subKeys.length > 0) {
                                                                                return subKeys.map(key => {
                                                                                    const sub = BANNER_STATIC[key];
                                                                                    const cfg = bannerConfig.find(bc => bc.key === key);
                                                                                    const isSubEnabled = cfg?.enabled !== false;

                                                                                    if (!isSubEnabled && currentUser?.role !== 'admin') return null;

                                                                                    return (
                                                                                        <a
                                                                                            key={key}
                                                                                            href={sub.href || '#'}
                                                                                            target={sub.href ? '_blank' : '_self'}
                                                                                            rel="noopener noreferrer"
                                                                                            onClick={(e) => {
                                                                                                if (sub.isInternal) {
                                                                                                    e.preventDefault();
                                                                                                    setCurrentView(sub.view);
                                                                                                    setExpandedBanner(null);
                                                                                                }
                                                                                                updateStatistics('bannerClick', { bannerLabel: sub.label, user: currentUser?.username || 'Visitante' });
                                                                                            }}
                                                                                            className={`flex items-center gap-3 p-3 rounded-2xl border transition-all hover:-translate-y-1 hover:shadow-lg ${darkMode ? `bg-gradient-to-br ${sub.dark} border-gray-700/50 hover:border-blue-500/50` : `bg-gradient-to-br ${sub.light} border-gray-100 hover:border-blue-300`} ${!isSubEnabled ? 'opacity-40 grayscale' : ''}`}
                                                                                        >
                                                                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${darkMode ? sub.iconDark : sub.iconLight}`}>
                                                                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sub.icon} /></svg>
                                                                                            </div>
                                                                                            <div className="min-w-0">
                                                                                                <p className={`text-xs font-bold truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{sub.label}</p>
                                                                                                <p className={`text-[10px] truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{sub.description}</p>
                                                                                            </div>
                                                                                        </a>
                                                                                    );
                                                                                });
                                                                            }

                                                                            // Especial para Biblioteca
                                                                            if (s.modalId === 'biblioteca') {
                                                                                return BIBLIOTECA_CATEGORIAS.map(cat => (
                                                                                    <button
                                                                                        key={cat.id}
                                                                                        onClick={() => {
                                                                                            setBibliotecaCategoria(cat.id);
                                                                                            setBibliotecaModalOpen(true);
                                                                                            setExpandedBanner(null);
                                                                                        }}
                                                                                        className={`flex items-center gap-3 p-3 rounded-2xl border transition-all hover:-translate-y-1 hover:shadow-lg text-left ${darkMode ? `bg-gradient-to-br ${cat.colorDark} border-gray-700/50` : `bg-gradient-to-br ${cat.colorLight} border-gray-100`}`}
                                                                                    >
                                                                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${darkMode ? cat.iconDark : cat.iconLight}`}>
                                                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={cat.icon} /></svg>
                                                                                        </div>
                                                                                        <div className="min-w-0">
                                                                                            <p className={`text-xs font-bold truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{cat.label}</p>
                                                                                            <p className={`text-[10px] truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{cat.description}</p>
                                                                                        </div>
                                                                                    </button>
                                                                                ));
                                                                            }

                                                                            return null;
                                                                        })()}
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </React.Fragment>
                                                );
                                            }
                                            if (s.isInternal) {
                                                return (
                                                    <button
                                                        key={banner.id}
                                                        onClick={(e) => {
                                                            if (isEffectivelyFrozen) {
                                                                e.preventDefault();
                                                                alert('Este acesso está temporariamente indisponível. Em manutenção.');
                                                                return;
                                                            }
                                                            if (!isDisabledForUser) {
                                                                updateStatistics('bannerClick', {
                                                                    bannerLabel: s.label || banner.label,
                                                                    user: currentUser ? currentUser.username : 'Visitante'
                                                                });
                                                                setCurrentView('search');
                                                            }
                                                        }}
                                                        disabled={isDisabledForUser}
                                                        className={cardClass}
                                                        {...dragProps}
                                                    >
                                                        {content}
                                                    </button>
                                                );
                                            }
                                            return (
                                                <a
                                                    key={banner.id}
                                                    href={(isDisabledForUser || s.comingSoon || isEffectivelyFrozen) ? undefined : s.href}
                                                    target={(isDisabledForUser || s.comingSoon || isEffectivelyFrozen) ? undefined : '_blank'}
                                                    rel="noopener noreferrer"
                                                    className={cardClass}
                                                    onClick={(e) => {
                                                        if (isEffectivelyFrozen) {
                                                            e.preventDefault();
                                                            alert('Este acesso está temporariamente indisponível. Em manutenção.');
                                                        } else if (isDisabledForUser || s.comingSoon) {
                                                            e.preventDefault();
                                                        } else {
                                                            updateStatistics('bannerClick', {
                                                                bannerLabel: s.label || banner.label,
                                                                user: currentUser ? currentUser.username : 'Visitante'
                                                            });
                                                        }
                                                    }}
                                                    {...dragProps}
                                                >
                                                    {content}
                                                </a>
                                            );
                                        })}
                                </div>
                            </div>
                        )}

                        {(currentView === 'outros' || currentView === 'other-services') && (
                            <div className="animate-fadeInUp space-y-8">
                                <section>
                                    <div className="text-center relative py-4 flex flex-col items-center mb-8">
                                        <div className={`absolute left-1/2 -translate-x-1/2 top-1/2 -translate-y-1/2 w-24 h-24 blur-3xl rounded-full opacity-25 ${darkMode ? 'bg-blue-500' : 'bg-blue-400'}`}></div>

                                        {/* Logo Branding Outros Serviços */}
                                        <div className="relative mb-4 animate-fadeInDown">
                                            <img
                                                src="image/ecossistema3.png"
                                                alt="EcoSistema Logo"
                                                className="h-14 md:h-16 w-auto object-contain drop-shadow-xl"
                                            />
                                        </div>

                                        <h2 className={`relative text-[10px] md:text-xs font-black tracking-[0.4em] uppercase mb-1 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                                            Central de Serviços Internos
                                        </h2>
                                        <div className={`mt-4 mx-auto w-12 h-1 rounded-full ${darkMode ? 'bg-gray-700' : 'bg-gray-200'}`}></div>
                                    </div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                        {bannerConfig
                                            .filter(b => (BANNER_STATIC[b.key]?.menu || 'home') === 'outros')
                                            .filter(b => currentUser?.role === 'admin' || b.enabled)
                                            .map((banner, index) => {
                                                const s = BANNER_STATIC[banner.key];
                                                if (!s) return null;
                                                const isAdmin = currentUser?.role === 'admin';
                                                const isDisabledForUser = !banner.enabled && !isAdmin;
                                                const isFrozen = banner.isFrozen === true;
                                                const isEffectivelyFrozen = isFrozen && !isAdmin;

                                                const cardClass = `flex flex-col items-center justify-center p-6 rounded-2xl border-2 transition-all transform hover:-translate-y-2 hover:shadow-2xl ${darkMode
                                                    ? `bg-gradient-to-br ${s.dark}`
                                                    : `bg-gradient-to-br ${s.light}`
                                                    } group relative overflow-hidden ${isDisabledForUser ? 'opacity-40 cursor-default hover:translate-y-0 hover:shadow-none' : ''
                                                    } ${(s.comingSoon || isEffectivelyFrozen) ? 'cursor-default hover:translate-y-0 hover:shadow-none opactity-75' : ''
                                                    }`;

                                                const content = (
                                                    <div
                                                        style={{
                                                            transform: 'rotateX(2deg) rotateY(-1deg) translateZ(0)',
                                                            transformStyle: 'preserve-3d',
                                                            transition: 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)',
                                                            width: '100%',
                                                            height: '100%',
                                                            display: 'flex',
                                                            flexDirection: 'column',
                                                            alignItems: 'center',
                                                            justifyContent: 'center'
                                                        }}
                                                        onMouseEnter={(e) => {
                                                            e.currentTarget.style.transform = 'rotateX(4deg) rotateY(-2deg) translateZ(40px)';
                                                        }}
                                                        onMouseLeave={(e) => {
                                                            e.currentTarget.style.transform = 'rotateX(2deg) rotateY(-1deg) translateZ(0)';
                                                        }}
                                                    >
                                                        {isAdmin && (
                                                            <div className="absolute top-3 right-3 z-20 flex items-center gap-2" onClick={e => e.stopPropagation()}>
                                                                <div className={`text-[9px] font-black uppercase tracking-tighter ${isFrozen ? (banner.freezeReason === 'construction' ? 'text-amber-500' : 'text-red-500 animate-pulse') : (darkMode ? 'text-green-400' : 'text-green-600')}`}>
                                                                    {isFrozen ? (banner.freezeReason === 'construction' ? 'EM OBRAS' : 'REVISÃO') : 'ATIVO'}
                                                                </div>
                                                                <button
                                                                    onClick={(e) => {
                                                                        e.preventDefault();
                                                                        e.stopPropagation();
                                                                        if (isFrozen) {
                                                                            handleFreezeToggleGlobal(banner);
                                                                        } else {
                                                                            setFreezeModalBanner(banner);
                                                                        }
                                                                    }}
                                                                    className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${isFrozen ? (banner.freezeReason === 'construction' ? 'bg-amber-500' : 'bg-red-500') : (darkMode ? 'bg-gray-700' : 'bg-gray-200')}`}
                                                                    title={isFrozen ? "Descongelar serviço" : "Congelar serviço"}
                                                                >
                                                                    <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${isFrozen ? 'translate-x-4' : 'translate-x-0'}`} />
                                                                </button>
                                                            </div>
                                                        )}
                                                        <div className={`absolute inset-0 opacity-0 group-hover:opacity-10 transition-opacity duration-300 ${darkMode ? (s.hoverBg?.dark || 'bg-white') : (s.hoverBg?.light || 'bg-blue-600')}`}></div>
                                                        <div className={`w-16 h-16 rounded-full flex items-center justify-center mb-4 ${darkMode ? s.iconDark : s.iconLight} shadow-inner pointer-events-none overflow-hidden`}>
                                                            {s.imageIcon ? (
                                                                <img src={s.imageIcon} alt="" className={s.imageClass || 'w-full h-full object-cover'} />
                                                            ) : (
                                                                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={s.icon} />
                                                                </svg>
                                                            )}
                                                        </div>
                                                        <h3 className={`text-xl font-bold mb-2 text-center pointer-events-none ${darkMode ? 'text-white' : 'text-gray-900'}`}>{s.label || banner.label}</h3>
                                                        <p className={`text-sm text-center leading-relaxed pointer-events-none ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{s.description}</p>
                                                        {isFrozen && !isAdmin && (
                                                            <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-gray-900/10 dark:bg-black/30 backdrop-blur-[2px] rounded-3xl animate-fadeIn">
                                                                <div className={`px-4 py-2 rounded-xl shadow-lg border backdrop-blur-md flex items-center gap-2 ${banner.freezeReason === 'construction'
                                                                    ? 'bg-amber-500/90 border-amber-400 text-white'
                                                                    : 'bg-red-500/90 border-red-400 text-white'
                                                                    }`}>
                                                                    {banner.freezeReason === 'construction' ? (
                                                                        <svg className="w-5 h-5 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
                                                                    ) : (
                                                                        <svg className="w-5 h-5 animate-spin-slow" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                                                                    )}
                                                                    <span className="font-bold text-sm tracking-wide">
                                                                        {banner.freezeReason === 'construction' ? 'EM CONSTRUÇÃO' : 'EM MANUTENÇÃO'}
                                                                    </span>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                );

                                                return (
                                                    <a
                                                        key={banner.id}
                                                        href={(isDisabledForUser || s.comingSoon || isEffectivelyFrozen) ? undefined : s.href}
                                                        target={(isDisabledForUser || s.comingSoon || isEffectivelyFrozen) ? undefined : '_blank'}
                                                        rel="noopener noreferrer"
                                                        className={cardClass}
                                                        onClick={(e) => {
                                                            if (isEffectivelyFrozen) {
                                                                e.preventDefault();
                                                                alert('Este acesso está temporariamente indisponível. Em manutenção.');
                                                            } else if (isDisabledForUser || s.comingSoon) {
                                                                e.preventDefault();
                                                            } else {
                                                                updateStatistics('bannerClick', {
                                                                    bannerLabel: s.label || banner.label,
                                                                    user: currentUser ? currentUser.username : 'Visitante'
                                                                });
                                                            }
                                                        }}
                                                    >
                                                        {content}
                                                    </a>
                                                );
                                            })}
                                    </div>
                                </section>
                            </div>
                        )}

                        {currentView === 'search' && (
                            <div className={`${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} rounded-2xl shadow-2xl border backdrop-blur-sm p-8 mb-8 animate-fadeInUp`} style={{ animationDelay: '0.2s' }}>
                                <div className="mb-8 text-center">
                                    <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                        Use a busca geral para encontrar por código do item, descrição do serviço, CNAE e descrição CNAE.
                                    </p>
                                </div>

                                <div
                                    onKeyDown={handleSearchKeyDown}
                                    className="mb-6 transition-all duration-500"
                                >
                                    <div className="space-y-2">
                                        <label className={`block text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                            Pesquisa Geral
                                        </label>
                                        <div className="relative">
                                            <input
                                                type="text"
                                                value={searchTerm}
                                                onChange={(e) => setSearchTerm(e.target.value)}
                                                placeholder="Digite qualquer termo para buscar em todos os campos..."
                                                className={`w-full pl-4 pr-4 py-3 rounded-lg border transition-all duration-200 focus:ring-2 focus:ring-blue-500 focus:border-transparent ${darkMode ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'}`}
                                            />
                                        </div>
                                    </div>
                                </div>

                                <div className="flex justify-center">
                                    <button
                                        onClick={handleSearch}
                                        disabled={isLoading}
                                        className={`px-8 py-4 rounded-xl font-semibold text-white transition-all duration-300 transform hover:scale-105 focus:outline-none focus:ring-4 focus:ring-green-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-3 ${isLoading ? 'bg-gray-500' : 'bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 shadow-lg hover:shadow-xl'}`}
                                    >
                                        {isLoading ? (
                                            <>
                                                <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
                                                Pesquisando...
                                            </>
                                        ) : (
                                            <>
                                                Realizar Consulta
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>
                        )}

                        {/* View Admin: Gestão de Usuários */}
                        {currentUser?.role === 'admin' && currentView === 'admin-users' && (
                            <div className={`mb-8 p-6 rounded-xl border-2 ${darkMode ? 'border-red-600 bg-gray-800' : 'border-red-300 bg-red-50'} animate-fadeInUp`}>
                                <h2 className={`text-2xl font-bold mb-6 ${darkMode ? 'text-red-400' : 'text-red-700'} flex items-center gap-2`}>
                                    <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                                    </svg>
                                    Gestão de Usuários
                                </h2>
                                {pendingUsers.length > 0 && (
                                    <div className={`mb-6 p-4 rounded-lg border-2 border-yellow-400 ${darkMode ? 'bg-yellow-900/20' : 'bg-yellow-50'}`}>
                                        <h3 className={`font-bold mb-3 ${darkMode ? 'text-yellow-400' : 'text-yellow-700'}`}>Solicitações pendentes ({pendingUsers.length})</h3>
                                        <div className="grid gap-3 md:grid-cols-2">
                                            {pendingUsers.map(user => (
                                                <div key={user.id} className={`p-3 rounded-lg flex justify-between items-center ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                    <div>
                                                        <p className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{user.name}</p>
                                                        <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{user.username}</p>
                                                    </div>
                                                    <div className="flex gap-2">
                                                        <button
                                                            onClick={() => handleAuthorizeUser(user.id)}
                                                            className="px-3 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg text-sm font-medium flex items-center gap-1.5 transition-colors"
                                                        >
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                                            </svg>
                                                            Autorizar
                                                        </button>
                                                        <button
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
                                                            className="px-3 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-medium flex items-center gap-1.5 transition-colors"
                                                        >
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                                            </svg>
                                                            Rejeitar
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                <div className={`rounded-lg border ${darkMode ? 'border-gray-700' : 'border-gray-200'} overflow-hidden`}>
                                    <AdminUsersTable
                                        darkMode={darkMode}
                                        adminUsersListKey={adminUsersListKey}
                                        onRefreshNeeded={() => {
                                            loadPendingUsers();
                                            setAdminUsersListKey(k => k + 1);
                                        }}
                                    />
                                </div>
                            </div>
                        )}

                        {/* View Admin: Controle de Banners */}
                        {currentUser?.role === 'admin' && currentView === 'admin-banners' && (
                            <AdminBannersPanel darkMode={darkMode} />
                        )}


                        {/* Painel de Auditoria */}
                        {currentUser?.role === 'admin' && currentView === 'admin-dashboard' && (
                            <div className="animate-fadeInUp space-y-6">
                                {/* Header */}
                                <div className={`flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl ${darkMode ? 'bg-gray-800/80 border border-gray-700/50' : 'bg-white border border-gray-100'} shadow-sm`}>
                                    <div>
                                        <div className="flex items-center gap-3 mb-1">
                                            <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-blue-500/20 text-blue-400' : 'bg-blue-50 text-blue-600'}`}>
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                                            </div>
                                            <h2 className={`text-2xl font-bold tracking-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>Central de Auditoria</h2>
                                        </div>
                                        <p className={`text-sm mb-2 ml-12 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Monitoramento de acessos à aplicação e utilização dos banners de serviço.</p>
                                        <div className="flex items-center gap-2 ml-12">
                                            <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${darkMode ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-green-50 text-green-700 border border-green-200'}`}>
                                                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
                                                Monitoramento Ativo
                                            </div>
                                            <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600'}`}>
                                                {(statistics?.searchHistory || []).length} eventos totais registrados
                                            </span>
                                        </div>
                                    </div>

                                    {/* Alertas de Segurança Proativos */}
                                    {(() => {
                                        const alerts = [];
                                        const history = statistics?.searchHistory || [];

                                        // Detectar 3+ falhas seguidas de login por Usuário ou IP
                                        const failureGroups = {};
                                        history.filter(a => a.action === 'login_failure' || a.action === 'login_failed').forEach(a => {
                                            const key = a.user || a.ipAddress || 'unknown';
                                            if (!failureGroups[key]) failureGroups[key] = [];
                                            failureGroups[key].push(a);
                                        });

                                        Object.entries(failureGroups).forEach(([key, items]) => {
                                            if (items.length >= 3) {
                                                alerts.push({
                                                    title: `Múltiplas falhas de login: ${key}`,
                                                    desc: `${items.length} tentativas malsucedidas detectadas.`,
                                                    severity: items.length >= 5 ? 'critical' : 'warning'
                                                });
                                            }
                                        });

                                        if (alerts.length === 0) return null;

                                        return (
                                            <div className="flex-1 max-w-md w-full">
                                                <div className={`p-4 rounded-xl border-2 animate-pulse shadow-lg ${darkMode ? 'bg-red-900/20 border-red-500/50' : 'bg-red-50 border-red-200'}`}>
                                                    <div className="flex items-center gap-3 mb-2">
                                                        <svg className="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                                                        <h4 className={`text-sm font-bold ${darkMode ? 'text-red-400' : 'text-red-700'}`}>Alertas de Segurança ({alerts.length})</h4>
                                                    </div>
                                                    <div className="space-y-2">
                                                        {alerts.slice(0, 2).map((alert, idx) => (
                                                            <div key={idx} className="text-xs">
                                                                <p className={`font-bold ${darkMode ? 'text-red-300' : 'text-red-800'}`}>{alert.title}</p>
                                                                <p className={`${darkMode ? 'text-red-400/70' : 'text-red-600'}`}>{alert.desc}</p>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })()}
                                    <div className="flex gap-3 flex-shrink-0">
                                        <button
                                            onClick={() => {
                                                const bannerHistory = (statistics?.searchHistory || []).filter(a => a.type === 'banner');
                                                if (bannerHistory.length === 0) { alert('Nenhum dado para exportar.'); return; }
                                                const rows = [['Timestamp', 'Usuário', 'Serviço Acessado']];
                                                bannerHistory.forEach(a => {
                                                    rows.push([
                                                        new Date(a.timestamp).toLocaleString('pt-BR'),
                                                        a.user || 'Visitante',
                                                        a.bannerLabel || '-'
                                                    ]);
                                                });
                                                const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
                                                const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
                                                const url = URL.createObjectURL(blob);
                                                const link = document.createElement('a');
                                                link.href = url;
                                                link.download = 'auditoria_acessos_' + new Date().toISOString().split('T')[0] + '.csv';
                                                link.click();
                                                URL.revokeObjectURL(url);
                                            }}
                                            className={`px-4 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 transition-all ${darkMode ? 'bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 border border-blue-500/20' : 'bg-blue-50 text-blue-600 hover:bg-blue-100 border border-blue-200'}`}
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                                            Exportar CSV
                                        </button>
                                        <button
                                            onClick={async () => {
                                                if (window.confirm('ALERTA: Isso apagará irreversivelmente todos os dados de auditoria registrados NO BANCO DE DADOS. Deseja continuar?')) {
                                                    try {
                                                        setIsAuditLoading(true);
                                                        await ApiService.clearAuditLogs();
                                                        localStorage.removeItem('appStatistics'); // limpeza de cache legado
                                                        setStatistics({ totalAccesses: 0, totalSearches: 0, universalSearches: 0, advancedSearches: 0, totalBannerClicks: 0, lastAccess: null, dailyAccesses: {}, searchHistory: [], userSessions: {}, bannerClicks: {} });
                                                        setAuditUserFilter('');
                                                        alert('Dados de auditoria reiniciados e apagados do servidor com sucesso!');
                                                    } catch (e) {
                                                        alert('Erro ao limpar auditoria: ' + e.message);
                                                    } finally {
                                                        setIsAuditLoading(false);
                                                    }
                                                }
                                            }}
                                            className={`px-4 py-2.5 rounded-xl text-sm font-bold flex items-center gap-2 transition-all ${darkMode ? 'bg-red-500/10 text-red-500 hover:bg-red-500/20 border border-red-500/20' : 'bg-red-50 text-red-600 hover:bg-red-100 border border-red-200'} ${isAuditLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                                            disabled={isAuditLoading}
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                                            {isAuditLoading ? 'Carregando...' : 'Limpar Dados'}
                                        </button>
                                    </div>
                                </div>

                                {/* KPIs */}
                                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                                    {[
                                        { title: 'Acessos à Aplicação', value: statistics?.totalAccesses || 0, desc: 'Aberturas da plataforma', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6', colors: darkMode ? 'bg-blue-500/20 text-blue-400' : 'bg-blue-50 text-blue-600' },
                                        { title: 'Acessos a Serviços', value: statistics?.totalBannerClicks || 0, desc: 'Cliques em banners', icon: 'M13 10V3L4 14h7v7l9-11h-7z', colors: darkMode ? 'bg-emerald-500/20 text-emerald-400' : 'bg-emerald-50 text-emerald-600' },
                                        { title: 'Usuários Únicos', value: statistics?.userSessions?.['Usuários Únicos'] || 0, desc: 'Contas que já logaram', icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z', colors: darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-50 text-purple-600' },
                                        { title: 'Total de Usuários', value: statistics?.totalRegisteredUsers || 0, desc: 'Contas cadastradas', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z', colors: darkMode ? 'bg-indigo-500/20 text-indigo-400' : 'bg-indigo-50 text-indigo-600' },
                                        { title: 'Sessões Hoje', value: statistics?.dailyAccesses?.[new Date().toDateString()] || 0, desc: 'Logins na data atual', icon: 'M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z', colors: darkMode ? 'bg-orange-500/20 text-orange-400' : 'bg-orange-50 text-orange-600' }
                                    ].map((kpi, idx) => (
                                        <div key={idx} className={`p-5 rounded-2xl flex items-start justify-between gap-3 ${darkMode ? 'bg-gray-800/80 border border-gray-700/50' : 'bg-white border border-gray-100'} shadow-sm`}>
                                            <div className="min-w-0">
                                                <p className={`text-xs font-semibold mb-1 uppercase tracking-wider truncate ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{kpi.title}</p>
                                                <h3 className={`text-3xl font-black tracking-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>{kpi.value}</h3>
                                                <p className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{kpi.desc}</p>
                                            </div>
                                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${kpi.colors}`}>
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={kpi.icon} /></svg>
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                {/* Analytics Row */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                    {/* Acessos a Serviços por Usuário */}
                                    <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800/80 border border-gray-700/50' : 'bg-white border border-gray-100'} shadow-sm`}>
                                        <div className="flex items-center gap-3 mb-5">
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                                            </div>
                                            <h3 className={`font-bold text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Acessos a Serviços por Usuário</h3>
                                        </div>
                                        {(() => {
                                            const bannerEvents = (statistics?.searchHistory || []).filter(a => a.type === 'banner');
                                            const userStats = bannerEvents.reduce((acc, a) => { const u = a.user || 'Visitante'; acc[u] = (acc[u] || 0) + 1; return acc; }, {});
                                            const sorted = Object.entries(userStats).sort((a, b) => b[1] - a[1]).slice(0, 6);
                                            const max = sorted[0]?.[1] || 1;
                                            return sorted.length > 0 ? (
                                                <div className="space-y-3">
                                                    {sorted.map(([user, count], i) => (
                                                        <div key={i}>
                                                            <div className="flex justify-between items-center mb-1">
                                                                <span className={`text-xs font-semibold truncate max-w-[200px] ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{user}</span>
                                                                <span className={`text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0 ml-2 ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600'}`}>{count} acessos</span>
                                                            </div>
                                                            <div className={`w-full h-2 rounded-full overflow-hidden ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                                                                <div className={`h-full rounded-full transition-all duration-700 ${i === 0 ? 'bg-gradient-to-r from-purple-500 to-indigo-500' : darkMode ? 'bg-purple-500/50' : 'bg-purple-300'}`} style={{ width: `${Math.round((count / max) * 100)}%` }}></div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className={`flex flex-col items-center justify-center py-8 rounded-xl border border-dashed ${darkMode ? 'border-gray-700 bg-gray-800/30' : 'border-gray-200 bg-gray-50'}`}>
                                                    <p className={`text-xs font-medium ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Nenhum acesso a serviço registrado ainda.</p>
                                                </div>
                                            );
                                        })()}
                                    </div>

                                    {/* Top Serviços */}
                                    <div className={`p-6 rounded-2xl ${darkMode ? 'bg-gray-800/80 border border-gray-700/50' : 'bg-white border border-gray-100'} shadow-sm`}>
                                        <div className="flex items-center gap-3 mb-5">
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-emerald-500/20 text-emerald-400' : 'bg-emerald-100 text-emerald-600'}`}>
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" /></svg>
                                            </div>
                                            <h3 className={`font-bold text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Top Serviços Acessados</h3>
                                        </div>
                                        {Object.keys(statistics?.bannerClicks || {}).length > 0 ? (
                                            <div className="space-y-3">
                                                {Object.entries(statistics?.bannerClicks || {})
                                                    .sort((a, b) => b[1] - a[1])
                                                    .slice(0, 6)
                                                    .map(([banner, clicks], idx) => {
                                                        const max = Math.max(...Object.values(statistics?.bannerClicks || {}));
                                                        return (
                                                            <div key={idx}>
                                                                <div className="flex justify-between items-center mb-1">
                                                                    <span className={`text-xs font-semibold truncate max-w-[200px] ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{banner}</span>
                                                                    <span className={`text-xs font-bold px-2 py-0.5 rounded-full flex-shrink-0 ml-2 ${darkMode ? 'bg-emerald-500/15 text-emerald-400' : 'bg-emerald-50 text-emerald-700'}`}>{clicks} cliques</span>
                                                                </div>
                                                                <div className={`w-full h-2 rounded-full overflow-hidden ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                                                                    <div className={`h-full rounded-full transition-all duration-700 ${idx === 0 ? 'bg-gradient-to-r from-emerald-500 to-teal-500' : darkMode ? 'bg-emerald-500/40' : 'bg-emerald-300'}`} style={{ width: `${Math.round((clicks / max) * 100)}%` }}></div>
                                                                </div>
                                                            </div>
                                                        );
                                                    })}
                                            </div>
                                        ) : (
                                            <div className={`flex flex-col items-center justify-center py-8 rounded-xl border border-dashed ${darkMode ? 'border-gray-700 bg-gray-800/30' : 'border-gray-200 bg-gray-50'}`}>
                                                <p className={`text-xs font-medium ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Nenhum serviço acessado ainda.</p>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Log de Acessos a Serviços */}
                                <div className={`rounded-2xl overflow-hidden ${darkMode ? 'bg-gray-800/80 border border-gray-700/50' : 'bg-white border border-gray-100'} shadow-sm`}>
                                    {/* Filter Bar */}
                                    <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-6 py-4 border-b ${darkMode ? 'border-gray-700/50' : 'border-gray-100'}`}>
                                        <div className="flex items-center gap-3">
                                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${darkMode ? 'bg-emerald-500/20 text-emerald-400' : 'bg-emerald-50 text-emerald-600'}`}>
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                                            </div>
                                            <h3 className={`font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Log de Acessos a Serviços</h3>
                                            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-500'}`}>
                                                {(statistics?.searchHistory || []).filter(a => a.type === 'banner').filter(a => auditUserFilter === '' || a.user === auditUserFilter).length} registros
                                            </span>
                                        </div>
                                        <div className="flex flex-wrap items-center gap-3">
                                            <select
                                                value={auditUserFilter}
                                                onChange={e => setAuditUserFilter(e.target.value)}
                                                className={`text-xs font-semibold rounded-xl px-3 py-1.5 border outline-none transition-colors ${darkMode ? 'bg-gray-800 border-gray-700 text-gray-300' : 'bg-white border-gray-200 text-gray-600'}`}
                                            >
                                                <option value="">Todos os usuários</option>
                                                {[...new Set((statistics?.searchHistory || []).map(a => a.user).filter(Boolean))].map(u => (
                                                    <option key={u} value={u}>{u}</option>
                                                ))}
                                            </select>

                                            <select
                                                value={auditTypeFilter}
                                                onChange={e => setAuditTypeFilter(e.target.value)}
                                                className={`text-xs font-semibold rounded-xl px-3 py-1.5 border outline-none transition-colors ${darkMode ? 'bg-gray-800 border-gray-700 text-gray-300' : 'bg-white border-gray-200 text-gray-600'}`}
                                            >
                                                <option value="">Todos os eventos</option>
                                                <option value="banner">Acessos a Serviços</option>
                                                <option value="login_failure">Falhas de Login</option>
                                                <option value="login">Logins com Sucesso</option>
                                                <option value="admin">Ações Administrativas</option>
                                            </select>
                                        </div>
                                    </div>
                                    {/* Table */}
                                    <div className="overflow-x-auto">
                                        <div className="max-h-[420px] overflow-y-auto custom-scrollbar">
                                            {(() => {
                                                const filtered = (statistics?.searchHistory || [])
                                                    .filter(a => auditUserFilter === '' || a.user === auditUserFilter)
                                                    .filter(a => {
                                                        if (auditTypeFilter === '') return true;
                                                        if (auditTypeFilter === 'banner') return a.type === 'banner' || a.action === 'banner_clicked';
                                                        if (auditTypeFilter === 'login_failure') return a.action === 'login_failure' || a.action === 'login_failed' || a.action === 'login_failed_password';
                                                        if (auditTypeFilter === 'login') return a.action === 'login_success' || (a.type === 'access' && a.success !== false);
                                                        if (auditTypeFilter === 'admin') return a.action?.startsWith('admin_') || a.action?.includes('user_');
                                                        return true;
                                                    })
                                                    .slice().reverse();
                                                return filtered.length > 0 ? (
                                                    <table className="w-full text-sm">
                                                        <thead className={`sticky top-0 z-10 ${darkMode ? 'bg-gray-800/95 border-b border-gray-700/50' : 'bg-gray-50 border-b border-gray-100'}`}>
                                                            <tr>
                                                                {['Timestamp', 'Usuário', 'Ação / Evento', 'Detalhes'].map(h => (
                                                                    <th key={h} className={`px-4 py-3 text-left text-xs font-bold uppercase tracking-wider whitespace-nowrap ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{h}</th>
                                                                ))}
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {filtered.map((a, i) => (
                                                                <tr key={i} className={`border-b transition-colors ${darkMode ? 'border-gray-700/40 hover:bg-gray-700/30' : 'border-gray-50 hover:bg-gray-50/80'}`}>
                                                                    <td className={`px-4 py-3 whitespace-nowrap text-xs font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                                                        {new Date(a.timestamp).toLocaleString('pt-BR', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                                                    </td>
                                                                    <td className={`px-4 py-3 whitespace-nowrap text-xs font-bold ${darkMode ? 'text-gray-200' : 'text-gray-800'}`}>
                                                                        {a.user || 'Visitante'}
                                                                    </td>
                                                                    <td className="px-4 py-3 whitespace-nowrap">
                                                                        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ${a.success === false || a.action?.includes('failure') ? (darkMode ? 'bg-red-500/15 text-red-400' : 'bg-red-50 text-red-700') : (darkMode ? 'bg-emerald-500/15 text-emerald-400' : 'bg-emerald-50 text-emerald-700')}`}>
                                                                            <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${a.success === false || a.action?.includes('failure') ? 'bg-red-500' : 'bg-emerald-500'}`}></span>
                                                                            {a.action === 'banner_clicked' || a.type === 'banner' ? 'Acesso Serviço' :
                                                                                a.action === 'login_failure' ? 'Falha Login' :
                                                                                    a.action === 'login_success' ? 'Login' :
                                                                                        a.action || a.type}
                                                                        </span>
                                                                    </td>
                                                                    <td className={`px-4 py-3 text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                                        {a.bannerLabel || a.details?.reason || a.details?.username || (typeof a.details === 'string' ? a.details : JSON.stringify(a.details)) || '—'}
                                                                    </td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                ) : (
                                                    <div className={`flex flex-col items-center justify-center py-16 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                        <svg className="w-10 h-10 mb-3 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>
                                                        <p className="text-sm font-medium">Nenhum acesso a serviço registrado.</p>
                                                        <p className="text-xs mt-1 opacity-70">Os acessos via banners aparecerão aqui.</p>
                                                    </div>
                                                );
                                            })()}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Modal Sub-Banners — Prefeitura Moderna */}
                        {dteModalOpen && (
                            <div
                                className="fixed inset-0 z-50 flex items-center justify-center p-4"
                                style={{ backgroundColor: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
                                onClick={() => setDteModalOpen(false)}
                            >
                                <div
                                    className={`relative w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden animate-fadeInUp ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-white border border-gray-200'}`}
                                    onClick={e => e.stopPropagation()}
                                >
                                    {/* Header */}
                                    <div className={`flex items-center justify-between px-6 py-5 border-b ${darkMode ? 'border-gray-700/60 bg-gradient-to-r from-rose-900/40 to-pink-900/40' : 'border-rose-100 bg-gradient-to-r from-rose-50 to-pink-50'}`}>
                                        <div className="flex items-center gap-3">
                                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center overflow-hidden ${darkMode ? 'bg-rose-500/20' : 'bg-white shadow-sm'}`}>
                                                <img src="image/bauhaus.png" className="w-8 h-8 rounded-full object-cover" alt="Prefeitura Moderna" />
                                            </div>
                                            <div>
                                                <h2 className={`text-lg font-bold leading-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>Prefeitura Moderna</h2>
                                                <p className={`text-xs ${darkMode ? 'text-rose-300/70' : 'text-rose-500'}`}>Selecione o serviço desejado</p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setDteModalOpen(false)}
                                            className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${darkMode ? 'text-gray-400 hover:bg-gray-700 hover:text-white' : 'text-gray-500 hover:bg-white/80 hover:text-gray-900'}`}
                                        >
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                                        </button>
                                    </div>
                                    <div className="p-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        {DTE_SUB_BANNERS_KEYS.map(key => {
                                            const sub = BANNER_STATIC[key];
                                            const config = bannerConfig.find(b => b.key === key);
                                            const isEnabled = config ? config.enabled : !sub.adminOnly;
                                            const isAdmin = currentUser?.role === 'admin';

                                            if (!isEnabled && !isAdmin) return null;

                                            const isPlaceholder = sub.href === '#';
                                            return (
                                                <a
                                                    key={key}
                                                    href={isPlaceholder ? undefined : sub.href}
                                                    target={isPlaceholder ? undefined : '_blank'}
                                                    rel="noopener noreferrer"
                                                    onClick={isPlaceholder ? e => e.preventDefault() : (e) => {
                                                        updateStatistics('banner_clicked', {
                                                            bannerKey: key,
                                                            bannerLabel: sub.label,
                                                            user: currentUser?.username || 'unknown',
                                                            menu: 'dte-sub'
                                                        });
                                                    }}
                                                    className={`group flex items-start gap-4 p-4 rounded-xl border bg-gradient-to-br transition-all duration-200 ${isPlaceholder ? 'opacity-50 cursor-not-allowed pointer-events-none' : 'cursor-pointer'} ${darkMode ? sub.dark : sub.light}`}
                                                >
                                                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 transition-transform duration-200 group-hover:scale-110 ${darkMode ? sub.iconDark : sub.iconLight}`}>
                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sub.icon} /></svg>
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center justify-between gap-2">
                                                            <div className="flex items-center gap-2 min-w-0">
                                                                <span className={`text-sm font-bold truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{sub.label}</span>
                                                            </div>
                                                            {!isPlaceholder && (
                                                                <svg className={`w-4 h-4 flex-shrink-0 opacity-50 group-hover:opacity-100 transition-opacity ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                                                            )}
                                                        </div>
                                                        <p className={`text-xs mt-0.5 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{sub.description}</p>
                                                    </div>
                                                </a>
                                            );
                                        })}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Modal Sub-Banners — Consultas Fiscais */}
                        {consultasModalOpen && (
                            <div
                                className="fixed inset-0 z-50 flex items-center justify-center p-4"
                                style={{ backgroundColor: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
                                onClick={() => setConsultasModalOpen(false)}
                            >
                                <div
                                    className={`relative w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden animate-fadeInUp ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-white border border-gray-200'}`}
                                    onClick={e => e.stopPropagation()}
                                >
                                    <div className={`flex items-center justify-between px-6 py-5 border-b ${darkMode ? 'border-gray-700/60 bg-gradient-to-r from-blue-900/40 to-purple-900/40' : 'border-blue-100 bg-gradient-to-r from-blue-50 to-purple-50'}`}>
                                        <div className="flex items-center gap-3">
                                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center overflow-hidden ${darkMode ? 'bg-blue-500/20 text-blue-400' : 'bg-white text-blue-600 shadow-sm'}`}>
                                                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                                            </div>
                                            <div>
                                                <h2 className={`text-lg font-bold leading-tight ${darkMode ? 'text-white' : 'text-gray-900'}`}>Consultas Fiscais</h2>
                                                <p className={`text-xs ${darkMode ? 'text-blue-300/70' : 'text-blue-600'}`}>Selecione o serviço de consulta desejado</p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setConsultasModalOpen(false)}
                                            className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${darkMode ? 'text-gray-400 hover:bg-gray-700 hover:text-white' : 'text-gray-500 hover:bg-white/80 hover:text-gray-900'}`}
                                        >
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                                        </button>
                                    </div>
                                    <div className="p-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        {CONSULTAS_FISCAIS_SUB_BANNERS_KEYS.map(key => {
                                            const sub = BANNER_STATIC[key];
                                            const config = bannerConfig.find(b => b.key === key);
                                            const isEnabled = config ? config.enabled : !sub.adminOnly;
                                            const isAdmin = currentUser?.role === 'admin';

                                            if (!isEnabled && !isAdmin) return null;

                                            const isPlaceholder = sub.href && sub.href === '#';
                                            const clickHandler = (e) => {
                                                if (isPlaceholder) {
                                                    e.preventDefault();
                                                    return;
                                                }
                                                // Log access
                                                updateStatistics('banner_clicked', {
                                                    bannerKey: key,
                                                    bannerLabel: sub.label,
                                                    user: currentUser?.username || 'unknown',
                                                    menu: 'consultas-sub'
                                                });
                                                if (sub.isInternal) {
                                                    e.preventDefault();
                                                    setConsultasModalOpen(false);
                                                    setCurrentView(sub.view);
                                                }
                                            };
                                            return (
                                                <a
                                                    key={key}
                                                    href={sub.isInternal ? '#' : (isPlaceholder ? undefined : sub.href)}
                                                    target={sub.isInternal || isPlaceholder ? undefined : '_blank'}
                                                    rel="noopener noreferrer"
                                                    onClick={clickHandler}
                                                    className={`group flex items-start gap-4 p-4 rounded-xl border bg-gradient-to-br transition-all duration-200 ${isPlaceholder ? 'opacity-50 cursor-not-allowed pointer-events-none' : 'cursor-pointer'} ${darkMode ? sub.dark : sub.light}`}
                                                >
                                                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 transition-transform duration-200 group-hover:scale-110 ${darkMode ? sub.iconDark : sub.iconLight}`}>
                                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={sub.icon} /></svg>
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center justify-between gap-2">
                                                            <div className="flex items-center gap-2 min-w-0">
                                                                <span className={`text-sm font-bold truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{sub.label}</span>
                                                            </div>
                                                            {!isPlaceholder && !sub.isInternal && (
                                                                <svg className={`w-4 h-4 flex-shrink-0 opacity-50 group-hover:opacity-100 transition-opacity ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                                                            )}
                                                        </div>
                                                        <p className={`text-xs mt-0.5 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{sub.description}</p>
                                                    </div>
                                                </a>
                                            );
                                        })}
                                    </div>
                                </div>
                            </div>
                        )}

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

                        {isLoading && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                                <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} p-8 rounded-2xl shadow-2xl flex flex-col items-center`}>
                                    <div className="relative mb-4">
                                        <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-200 border-t-blue-600"></div>
                                        <div className="absolute inset-0 animate-ping rounded-full h-16 w-16 border-2 border-blue-400"></div>
                                    </div>
                                    <p className={`text-lg font-medium ${darkMode ? 'text-white' : 'text-gray-800'}`}>Processando consulta...</p>
                                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'} mt-2`}>Aguarde um momento</p>
                                </div>
                            </div>
                        )}

                        {isModalOpen && (
                            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                                <div
                                    className="absolute inset-0 backdrop-blur-sm"
                                    onClick={closeModal}
                                ></div>

                                <div className={`relative w-full max-w-7xl max-h-[90vh] rounded-2xl shadow-2xl overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                    <div className="px-6 py-4 border-b flex justify-between items-center bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 text-white">
                                        <h2 className="text-xl font-semibold flex items-center">
                                            <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                            </svg>
                                            Resultados da Consulta
                                        </h2>
                                        <div className="flex gap-3 items-center">
                                            <span className="text-sm bg-white bg-opacity-20 backdrop-filter backdrop-blur-sm px-4 py-2 rounded-full flex items-center gap-2">
                                                <div className="status-indicator status-active"></div>
                                                {modalResults.length} resultados
                                            </span>
                                            <button
                                                onClick={closeModal}
                                                className="p-2 hover:bg-white hover:bg-opacity-20 rounded-full transition-all duration-200"
                                            >
                                                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                                </svg>
                                            </button>
                                        </div>
                                    </div>

                                    {noResults ? (
                                        <div className="text-center py-16 animate-fadeInUp">
                                            <svg className="mx-auto h-16 w-16 text-gray-400 mb-4 animate-pulse-custom" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6-4h6m2 5.291A7.962 7.962 0 0112 15c-2.34 0-4.47-.881-6.08-2.33" />
                                            </svg>
                                            <h3 className={`text-lg font-medium ${darkMode ? 'text-gray-300' : 'text-gray-900'} mb-2`}>
                                                Nenhum resultado encontrado
                                            </h3>
                                            <p className={`${darkMode ? 'text-gray-400' : 'text-gray-500'} mb-4`}>
                                                Tente ajustar o termo de pesquisa ou usar filtros diferentes.
                                            </p>
                                        </div>
                                    ) : (
                                        <div className="animate-fadeInUp">
                                            <div className="overflow-x-auto custom-scrollbar px-6" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
                                                <table className={`min-w-full ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                    <thead className={`sticky top-0 ${darkMode ? 'bg-gray-700' : 'bg-gray-50'} z-10`}>
                                                        <tr>
                                                            <th className={`px-4 py-3 text-center text-xs font-medium uppercase tracking-wider ${darkMode ? 'text-gray-300 border-gray-600' : 'text-gray-500 border-gray-200'
                                                                } border-b`}>
                                                                Código do Item
                                                            </th>
                                                            <th className={`px-4 py-3 text-center text-xs font-medium uppercase tracking-wider ${darkMode ? 'text-gray-300 border-gray-600' : 'text-gray-500 border-gray-200'
                                                                } border-b`}>
                                                                Descrição do Serviço
                                                            </th>
                                                            <th className={`px-4 py-3 text-center text-xs font-medium uppercase tracking-wider ${darkMode ? 'text-gray-300 border-gray-600' : 'text-gray-500 border-gray-200'
                                                                } border-b`}>
                                                                CNAE
                                                            </th>
                                                            <th className={`px-4 py-3 text-center text-xs font-medium uppercase tracking-wider ${darkMode ? 'text-gray-300 border-gray-600' : 'text-gray-500 border-gray-200'
                                                                } border-b`}>
                                                                Descrição CNAE
                                                            </th>
                                                            <th className={`px-4 py-3 text-center text-xs font-medium uppercase tracking-wider ${darkMode ? 'text-gray-300 border-gray-600' : 'text-gray-500 border-gray-200'
                                                                } border-b`}>
                                                                Alíquota ISS
                                                            </th>
                                                        </tr>
                                                    </thead>
                                                    <tbody className={`divide-y ${darkMode ? 'divide-gray-600' : 'divide-gray-200'}`}>
                                                        {modalResults.slice(0, 100).map((item, index) => (
                                                            <tr key={index} className={`hover:${darkMode ? 'bg-gray-700' : 'bg-gray-50'} transition-all duration-300 hover:scale-[1.02]`}>
                                                                <td className={`px-4 py-4 whitespace-nowrap text-sm text-center ${darkMode ? 'text-blue-300' : 'text-blue-600'
                                                                    } font-medium`}>
                                                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${darkMode ? 'bg-blue-900 text-blue-200' : 'bg-blue-100 text-blue-800'
                                                                        }`}>
                                                                        {item["LIST LC"].replace(/^0+/, '') || item["LIST LC"]}
                                                                    </span>
                                                                </td>
                                                                <td className={`px-4 py-4 text-sm text-center ${darkMode ? 'text-gray-300' : 'text-gray-900'
                                                                    } max-w-xs`}>
                                                                    <div className="line-clamp-3">
                                                                        {item["Descrição item da lista da Lei Complementar nº 001/2003 - CTM"]}
                                                                    </div>
                                                                </td>
                                                                <td className={`px-4 py-4 whitespace-nowrap text-sm text-center ${darkMode ? 'text-green-300' : 'text-green-600'
                                                                    } font-medium`}>
                                                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${darkMode ? 'bg-green-900 text-green-200' : 'bg-green-100 text-green-800'
                                                                        }`}>
                                                                        {(() => {
                                                                            const cnae = item["CNAE"].toString().replace(/[^0-9]/g, '');
                                                                            if (cnae.length >= 7) {
                                                                                const paddedCnae = cnae.padStart(7, '0');
                                                                                return `${paddedCnae.slice(0, 4)}-${paddedCnae.slice(4, 5)}/${paddedCnae.slice(5, 7)}`;
                                                                            }
                                                                            return item["CNAE"];
                                                                        })()}
                                                                    </span>
                                                                </td>
                                                                <td className={`px-4 py-4 text-sm text-center ${darkMode ? 'text-gray-300' : 'text-gray-900'
                                                                    } max-w-xs`}>
                                                                    <div className="line-clamp-3">
                                                                        {item["Descrição do CNAE"]}
                                                                    </div>
                                                                </td>
                                                                <td className={`px-4 py-4 whitespace-nowrap text-sm text-center font-bold ${darkMode ? 'text-yellow-300' : 'text-yellow-600'
                                                                    }`}>
                                                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border-2 ${darkMode ? 'bg-yellow-900 text-yellow-200 border-yellow-600' : 'bg-yellow-100 text-yellow-800 border-yellow-400'
                                                                        }`}>
                                                                        {item["Alíquota"]}
                                                                    </span>
                                                                </td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>

                                            <div className={`px-6 py-4 border-t ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'
                                                } rounded-b-lg`}>
                                                <div className="flex items-center justify-between">
                                                    <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'
                                                        }`}>
                                                        <span className="font-medium">
                                                            Mostrando {Math.min(100, modalResults.length)} de {modalResults.length} resultado{modalResults.length !== 1 ? 's' : ''}
                                                        </span>
                                                        {modalResults.length > 100 && (
                                                            <span className={`ml-2 text-xs px-2 py-1 rounded-full ${darkMode ? 'bg-yellow-900 text-yellow-200' : 'bg-yellow-100 text-yellow-800'
                                                                }`}>
                                                                Primeiros 100 resultados
                                                            </span>
                                                        )}
                                                    </div>
                                                    <div className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'
                                                        }`}>
                                                        💡 Refine sua busca para resultados mais específicos
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        <footer className={`relative z-[1] mt-8 text-center text-xs font-semibold leading-tight transition-colors duration-500 select-none pointer-events-none whitespace-nowrap px-4 py-2 rounded-full backdrop-blur-sm ${darkMode ? 'text-gray-400 bg-gray-900/20' : 'text-gray-500 bg-white/20'}`}>
                            <p>© 2026 Ecossistema DIAAF · <span className={`${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>Murilo Miguel</span> 🚀</p>
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
