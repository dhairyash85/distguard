import { Link, useLocation } from 'react-router-dom';
import { Shield, Activity, Download, ShieldCheck } from 'lucide-react';

export default function Navbar() {
    const location = useLocation();

    const isActive = (path) => {
        return location.pathname === path ? 'text-blue-400 bg-white/10' : 'text-gray-300 hover:text-white hover:bg-white/5';
    };

    return (
        <nav className="fixed top-0 left-0 right-0 z-50 backdrop-blur-md bg-black/30 border-b border-white/10">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-16">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-500/20 rounded-lg">
                            <Shield className="w-6 h-6 text-blue-400" />
                        </div>
                        <span className="text-xl font-bold bg-gradient-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">
                            DistGuard
                        </span>
                    </div>

                    <div className="flex gap-2">
                        <Link
                            to="/"
                            className={`px-4 py-2 rounded-lg transition-all duration-200 flex items-center gap-2 ${isActive('/')}`}
                        >
                            <Download className="w-4 h-4" />
                            <span>Download</span>
                        </Link>
                        <Link
                            to="/stats"
                            className={`px-4 py-2 rounded-lg transition-all duration-200 flex items-center gap-2 ${isActive('/stats')}`}
                        >
                            <Activity className="w-4 h-4" />
                            <span>Network Stats</span>
                        </Link>
                        <Link
                            to="/zkp"
                            className={`px-4 py-2 rounded-lg transition-all duration-200 flex items-center gap-2 ${isActive('/zkp')}`}
                        >
                            <ShieldCheck className="w-4 h-4" />
                            <span>ZK Proofs</span>
                        </Link>
                    </div>
                </div>
            </div>
        </nav>
    );
}
