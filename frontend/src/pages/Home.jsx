import { Download, Terminal, Database, ArrowRight, GitGraph, GitBranch } from 'lucide-react';
import Layout from '../components/Layout';

export default function Home() {
    const steps = [
        {
            icon: <GitBranch className="w-5 h-5 text-blue-400" />,
            title: "Download Project",
            desc: "Download the project files."
        },
        {
            icon: <Download className="w-5 h-5 text-blue-400" />,
            title: "Download Files",
            desc: "Get the necessary script and genesis block."
        },
        {
            icon: <Terminal className="w-5 h-5 text-purple-400" />,
            title: "Run Script",
            desc: "Execute join_network.sh in your terminal."
        },
        {
            icon: <Database className="w-5 h-5 text-green-400" />,
            title: "Sync Node",
            desc: "Your node will start syncing with the network."
        }
    ];

    return (
        <Layout>
            <div className="max-w-4xl mx-auto space-y-16">

                {/* Hero Section */}
                <div className="text-center space-y-6 pt-12">
                    <h1 className="text-5xl font-bold tracking-tight">
                        Join the <span className="bg-gradient-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">DistGuard</span> Network
                    </h1>
                    <p className="text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed">
                        Secure, decentralized anomaly detection powered by blockchain.
                        Download the tools to become a validator node today.
                    </p>

                    <div className="flex flex-col sm:flex-row gap-4 justify-center pt-8">
                        <a
                            href="https://github.com/dhairyash85/distguard"
                            // download
                            className="group px-8 py-4 bg-blue-600 hover:bg-blue-500 rounded-xl font-semibold transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20"
                        >
                            <GitBranch className="w-5 h-5 group-hover:-translate-y-1 transition-transform" />
                            Download Project
                        </a>
                        <a
                            href="/join_network.sh"
                            download
                            className="group px-8 py-4 bg-blue-600 hover:bg-blue-500 rounded-xl font-semibold transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20"
                        >
                            <Download className="w-5 h-5 group-hover:-translate-y-1 transition-transform" />
                            Download Script
                        </a>
                        <a
                            href="/genesis.json"
                            download
                            className="group px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl font-semibold transition-all flex items-center justify-center gap-2"
                        >
                            <Database className="w-5 h-5 text-gray-400 group-hover:text-white transition-colors" />
                            Download Genesis
                        </a>
                    </div>
                </div>

                {/* Steps Section */}
                <div className="grid md:grid-cols-4 gap-8 pt-12">
                    {steps.map((step, idx) => (
                        <div key={idx} className="p-6 rounded-2xl bg-white/5 border border-white/5 hover:border-white/10 transition-all group">
                            <div className="w-10 h-10 rounded-lg bg-black/50 border border-white/10 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                                {step.icon}
                            </div>
                            <h3 className="text-lg font-semibold mb-2">{step.title}</h3>
                            <p className="text-gray-400 text-sm">{step.desc}</p>
                        </div>
                    ))}
                </div>

                {/* Code Snippet */}
                <div className="mt-12 p-6 rounded-2xl bg-black/50 border border-white/10 font-mono text-sm text-gray-300 relative overflow-hidden group">
                    <div className="absolute top-0 right-0 p-4 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                            onClick={() => navigator.clipboard.writeText('chmod +x join_network.sh && ./join_network.sh')}
                            className="text-xs text-gray-500 hover:text-white"
                        >
                            Copy
                        </button>
                    </div>
                    <p className="text-gray-500 mb-2"># Quick Start</p>
                    <div className="flex items-center gap-2">
                        <span className="text-blue-400">$</span>
                        <span className="text-white">chmod +x join_network.sh && ./join_network.sh</span>
                    </div>
                </div>

            </div>
        </Layout>
    );
}
