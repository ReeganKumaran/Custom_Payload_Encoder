"""
Professional Reporter
Generates: Executive reports, JSON exports, detailed analysis
Purpose: Professional documentation for portfolio/interviews
"""

import json
import datetime
from pathlib import Path

class Reporter:
    def __init__(self):
        self.report_template = {
            'metadata': {},
            'executive_summary': {},
            'technical_details': {},
            'recommendations': [],
            'variants': []
        }
    
    def generate_report(self, variants, output_file):
        """Generate comprehensive report"""
        report = self._create_base_report(variants)
        
        # Save as JSON
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also generate human-readable version
        readable_file = output_file.replace('.json', '_readable.txt')
        self._generate_readable_report(report, readable_file)
        
        return report
    
    def _create_base_report(self, variants):
        """Create base report structure"""
        best_variant = max(variants, key=lambda x: x['evasion_score'])
        avg_evasion = sum(v['evasion_score'] for v in variants) / len(variants)
        
        report = {
            'metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'framework_version': '1.0',
                'author': 'Rahul Raval - Cybersecurity Engineer',
                'total_variants': len(variants)
            },
            'executive_summary': {
                'best_evasion_rate': best_variant['evasion_score'],
                'average_evasion_rate': round(avg_evasion, 2),
                'recommended_variant': best_variant['id'],
                'deployment_ready': best_variant['evasion_score'] >= 90
            },
            'technical_details': {
                'obfuscation_layers': best_variant['layers'],
                'payload_size_original': len(variants[0]['payload']) if variants else 0,
                'payload_size_obfuscated': len(best_variant['payload']),
                'size_increase_ratio': round(len(best_variant['payload']) / len(variants[0]['payload']), 2) if variants else 0
            },
            'variants': variants,
            'recommendations': self._generate_recommendations(variants)
        }
        
        return report
    
    def _generate_recommendations(self, variants):
        """Generate tactical recommendations"""
        recommendations = []
        
        best_score = max(v['evasion_score'] for v in variants)
        avg_score = sum(v['evasion_score'] for v in variants) / len(variants)
        
        if best_score >= 95:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Deployment',
                'recommendation': 'Excellent evasion achieved. Ready for red team deployment.',
                'technical_note': 'Consider this variant for production engagements.'
            })
        elif best_score >= 80:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Enhancement',
                'recommendation': 'Good evasion rate. Consider additional layers for critical operations.',
                'technical_note': 'Add more randomization or context-aware obfuscation.'
            })
        else:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Improvement',
                'recommendation': 'Low evasion rate detected. Requires additional obfuscation.',
                'technical_note': 'Consider polyglot techniques or advanced encoding.'
            })
        
        # Layer-specific recommendations
        layer_analysis = self._analyze_layer_effectiveness(variants)
        for layer, effectiveness in layer_analysis.items():
            if effectiveness < 0.5:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Layer Optimization',
                    'recommendation': f'Layer "{layer}" showing low effectiveness.',
                    'technical_note': f'Consider replacing or enhancing {layer} implementation.'
                })
        
        return recommendations
    
    def _analyze_layer_effectiveness(self, variants):
        """Analyze effectiveness of each obfuscation layer"""
        layer_scores = {}
        
        for variant in variants:
            for layer in variant['layers']:
                if layer not in layer_scores:
                    layer_scores[layer] = []
                layer_scores[layer].append(variant['evasion_score'])
        
        # Calculate average effectiveness per layer
        layer_effectiveness = {}
        for layer, scores in layer_scores.items():
            layer_effectiveness[layer] = sum(scores) / len(scores) / 100
        
        return layer_effectiveness
    
    def _generate_readable_report(self, report, output_file):
        """Generate human-readable report"""
        content = f"""
ADVANCED PAYLOAD OBFUSCATION FRAMEWORK
EVASION ANALYSIS REPORT
{'=' * 50}

Generated: {report['metadata']['generated_at']}
Author: {report['metadata']['author']}

EXECUTIVE SUMMARY
{'=' * 20}
• Best Evasion Rate: {report['executive_summary']['best_evasion_rate']}%
• Average Evasion Rate: {report['executive_summary']['average_evasion_rate']}%
• Recommended Variant: #{report['executive_summary']['recommended_variant']}
• Deployment Ready: {'✅ YES' if report['executive_summary']['deployment_ready'] else '❌ NO'}

TECHNICAL ANALYSIS
{'=' * 20}
• Obfuscation Layers: {' → '.join(report['technical_details']['obfuscation_layers'])}
• Size Increase: {report['technical_details']['size_increase_ratio']}x original
• Total Variants Tested: {report['metadata']['total_variants']}

VARIANT BREAKDOWN
{'=' * 20}
"""
        
        for variant in report['variants']:
            status_emoji = '✅' if variant['evasion_score'] >= 90 else '⚠️' if variant['evasion_score'] >= 70 else '❌'
            content += f"Variant {variant['id']}: {variant['evasion_score']}% evasion {status_emoji}\n"
        
        content += f"\nRECOMMENDATIONS\n{'=' * 20}\n"
        for i, rec in enumerate(report['recommendations'], 1):
            content += f"{i}. [{rec['priority']}] {rec['recommendation']}\n"
            content += f"   Technical: {rec['technical_note']}\n\n"
        
        content += f"\nFRAMEWORK SIGNATURE\n{'=' * 20}\n"
        content += "Advanced Payload Encoder & Obfuscation Framework\n"
        content += "Developed for educational red team research\n"
        content += "Author: Rahul Raval - Cybersecurity Engineering Student\n"
        
        with open(output_file, 'w') as f:
            f.write(content)
    
    def generate_json_export(self, variants, metadata=None):
        """Generate clean JSON export for integration"""
        export_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'variants': [],
            'summary': {
                'total_variants': len(variants),
                'best_score': max(v['evasion_score'] for v in variants) if variants else 0,
                'average_score': sum(v['evasion_score'] for v in variants) / len(variants) if variants else 0
            }
        }
        
        if metadata:
            export_data['metadata'] = metadata
        
        for variant in variants:
            export_data['variants'].append({
                'id': variant['id'],
                'evasion_score': variant['evasion_score'],
                'layers_applied': variant['layers'],
                'payload_length': len(variant['payload']),
                'status': variant['status']
            })
        
        return export_data
    
    def generate_executive_summary(self, variants):
        """Generate executive-level summary for presentations"""
        if not variants:
            return "No variants analyzed."
        
        best = max(variants, key=lambda x: x['evasion_score'])
        avg_score = sum(v['evasion_score'] for v in variants) / len(variants)
        
        summary = f"""
🎯 PAYLOAD OBFUSCATION ANALYSIS
{'=' * 40}

📊 RESULTS OVERVIEW:
• {len(variants)} variants generated and tested
• Best evasion rate: {best['evasion_score']}%
• Average evasion rate: {avg_score:.1f}%

🏆 RECOMMENDED DEPLOYMENT:
• Variant #{best['id']} - {best['evasion_score']}% evasion
• Layers: {' → '.join(best['layers'])}
• Status: {best['status']}

🛡️ SECURITY ASSESSMENT:
"""
        
        if best['evasion_score'] >= 95:
            summary += "• EXCELLENT - Bypasses most detection systems\n"
            summary += "• Ready for advanced red team operations\n"
        elif best['evasion_score'] >= 80:
            summary += "• GOOD - Suitable for most penetration testing\n"
            summary += "• Consider additional layers for high-security targets\n"
        else:
            summary += "• NEEDS IMPROVEMENT - Requires enhanced obfuscation\n"
            summary += "• Not recommended for production use\n"
        
        return summary