#!/usr/bin/env python3
"""
Generate PhishTrace System Architecture diagrams for academic report
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np
from pathlib import Path

_DOCS_DIR = Path(__file__).resolve().parent

# Set style for academic report
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['figure.dpi'] = 150

def create_overall_architecture():
    """Fig 1.1: Overall PhishTrace System Architecture"""
    fig, ax = plt.subplots(figsize=(14, 10))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 10)
    ax.axis('off')

    # Title
    ax.text(7, 9.5, 'Fig 1.1: Overall PhishTrace System Architecture',
            ha='center', va='center', fontsize=14, fontweight='bold')

    # Input Layer
    input_box = FancyBboxPatch((0.5, 7.5), 3, 1.2, boxstyle="round,pad=0.05",
                                facecolor='#E3F2FD', edgecolor='#1976D2', linewidth=2)
    ax.add_patch(input_box)
    ax.text(2, 8.1, 'INPUT LAYER', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(2, 7.7, '• Raw Email (.eml, .json)\n• Email Object\n• Batch Emails',
            ha='center', va='center', fontsize=8)

    # Preprocessing Layer
    pre_box = FancyBboxPatch((0.5, 5.8), 3, 1.2, boxstyle="round,pad=0.05",
                              facecolor='#E8F5E9', edgecolor='#388E3C', linewidth=2)
    ax.add_patch(pre_box)
    ax.text(2, 6.4, 'PREPROCESSING', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(2, 6.0, '• HTML cleaning\n• Tokenization\n• Stopword removal',
            ha='center', va='center', fontsize=8)

    # Feature Extraction - Text Pipeline
    text_box = FancyBboxPatch((0.5, 3.5), 3, 1.8, boxstyle="round,pad=0.05",
                               facecolor='#FFF3E0', edgecolor='#F57C00', linewidth=2)
    ax.add_patch(text_box)
    ax.text(2, 4.9, 'TEXT PIPELINE', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(2, 4.4, '• TF-IDF: 5,000 dims\n• DistilBERT: 768 dims\n• Keywords: 5\n• Subject: 3',
            ha='center', va='center', fontsize=8)

    # Feature Extraction - Structural Pipeline
    struct_box = FancyBboxPatch((4.5, 3.5), 3, 1.8, boxstyle="round,pad=0.05",
                                 facecolor='#F3E5F5', edgecolor='#7B1FA2', linewidth=2)
    ax.add_patch(struct_box)
    ax.text(6, 4.9, 'STRUCTURAL PIPELINE', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(6, 4.4, '• URL Analysis: 15\n• Domain: 12\n• Header: 10\n• Content: 8',
            ha='center', va='center', fontsize=8)

    # Feature Fusion
    fusion_box = FancyBboxPatch((2.5, 1.8), 3, 1.2, boxstyle="round,pad=0.05",
                                 facecolor='#FFEBEE', edgecolor='#C62828', linewidth=2)
    ax.add_patch(fusion_box)
    ax.text(4, 2.4, 'FEATURE FUSION', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(4, 2.0, '• Meta-learner\n• Normalization\n• 5,821 Features',
            ha='center', va='center', fontsize=8)

    # Model Inference
    model_box = FancyBboxPatch((6, 1.8), 3, 1.2, boxstyle="round,pad=0.05",
                                facecolor='#E0F7FA', edgecolor='#00695C', linewidth=2)
    ax.add_patch(model_box)
    ax.text(7.5, 2.4, 'MODEL INFERENCE', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(7.5, 2.0, '• TF-IDF + LogReg\n• TF-IDF + RF\n• DistilBERT + XGBoost',
            ha='center', va='center', fontsize=8)

    # Output Layer
    output_box = FancyBboxPatch((10.5, 3.5), 3, 1.8, boxstyle="round,pad=0.05",
                                 facecolor='#E8EAF6', edgecolor='#303F9F', linewidth=2)
    ax.add_patch(output_box)
    ax.text(12, 4.9, 'OUTPUT', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(12, 4.4, '• Phishing: Yes/No\n• Risk: High/Med/Low\n• Confidence: 0-100%',
            ha='center', va='center', fontsize=8)

    # API & Dashboard
    api_box = FancyBboxPatch((10.5, 1.8), 3, 1.2, boxstyle="round,pad=0.05",
                              facecolor='#ECEFF1', edgecolor='#455A64', linewidth=2)
    ax.add_patch(api_box)
    ax.text(12, 2.4, 'API / DASHBOARD', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(12, 2.0, '• FastAPI (Port 8000)\n• Streamlit (Port 8501)',
            ha='center', va='center', fontsize=8)

    # Arrows
    arrows = [
        ((2, 7.5), (2, 6.9)),
        ((2, 5.8), (2, 5.2)),
        ((2, 5.0), (0.7, 4.0)),
        ((2.5, 5.2), (2.5, 4.5)),
        ((3.5, 5.2), (5, 4.5)),
        ((6, 3.5), (4.5, 3.0)),
        ((2, 3.5), (3.5, 2.9)),
        ((4, 1.8), (6, 1.8)),
        ((7.5, 1.8), (10.5, 3.5)),
        ((7.5, 3.0), (12, 3.5)),
    ]
    for start, end in arrows:
        ax.annotate('', xy=end, xytext=start,
                    arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))

    # Output arrow
    ax.annotate('', xy=(10.5, 4.5), xytext=(9, 5),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig1_1_overall_architecture.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig1_1_overall_architecture.png")

def create_email_interface():
    """Fig 1.2: Example of Phishing Email Interface"""
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 8)
    ax.axis('off')

    ax.text(6, 7.5, 'Fig 1.2: Example of Phishing Email Interface',
            ha='center', va='center', fontsize=14, fontweight='bold')

    # Email container
    email_box = FancyBboxPatch((1, 1), 10, 5.5, boxstyle="round,pad=0.1",
                                facecolor='white', edgecolor='#C62828', linewidth=3)
    ax.add_patch(email_box)

    # Email header
    header_bg = FancyBboxPatch((1.2, 5.3), 9.6, 1, boxstyle="round,pad=0.02",
                               facecolor='#FFEBEE', edgecolor='none')
    ax.add_patch(header_bg)

    ax.text(2.5, 6.0, 'From:', fontweight='bold', fontsize=9)
    ax.text(2.5, 6.0, 'security@paypa1-secure.com [WARNING]', fontsize=9, color='#C62828')
    ax.text(1.5, 5.5, 'Subject:', fontweight='bold', fontsize=9)
    ax.text(2.7, 5.5, '[WARNING] URGENT: Verify Your Account Now!', fontsize=9, color='#C62828')

    # Red flags
    ax.text(1.5, 4.8, '⚠️ Suspicious Indicators:', fontweight='bold', fontsize=10, color='#C62828')

    indicators = [
        '- Misspelled "PayPal" -> "Paypa1"',
        '- Spoofed sender domain',
        '- Urgent language ("Verify Now")',
        '- Threat language ("Account will be suspended")',
        '- Suspicious URL: bit.ly/verify-account',
        '- Poor grammar and formatting'
    ]

    for i, indicator in enumerate(indicators):
        ax.text(1.5, 4.4 - i*0.4, indicator, fontsize=9, color='#B71C1C')

    # Phishing button
    phish_btn = FancyBboxPatch((4, 1.3), 4, 0.8, boxstyle="round,pad=0.05",
                               facecolor='#C62828', edgecolor='none')
    ax.add_patch(phish_btn)
    ax.text(6, 1.7, '[PHISHING DETECTED]', ha='center', va='center',
            fontsize=12, fontweight='bold', color='white')

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig1_2_email_interface.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig1_2_email_interface.png")

def create_traditional_methods():
    """Fig 2.1: Traditional Phishing Detection Methods"""
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6)
    ax.axis('off')

    ax.text(6, 5.5, 'Fig 2.1: Traditional Phishing Detection Methods',
            ha='center', va='center', fontsize=14, fontweight='bold')

    methods = [
        ('Rule-Based\nFiltering', '#E3F2FD', '#1565C0', 'Blacklists\nKeyword matching\nPattern rules'),
        ('Signature\nDetection', '#E8F5E9', '#2E7D32', 'Known malware\nHash matching\nURL matching'),
        ('Heuristic\nAnalysis', '#FFF3E0', '#EF6C00', 'Header analysis\nAttachment scanning\nContent rules'),
        ('Bayesian\nFiltering', '#F3E5F5', '#7B1FA2', 'Spam probability\nToken frequency\nPrior probabilities')
    ]

    for i, (name, bg, border, desc) in enumerate(methods):
        x = 0.8 + i * 2.8
        box = FancyBboxPatch((x, 1), 2.4, 3.5, boxstyle="round,pad=0.05",
                              facecolor=bg, edgecolor=border, linewidth=2)
        ax.add_patch(box)
        ax.text(x+1.2, 4, name, ha='center', va='center', fontsize=11, fontweight='bold')
        ax.text(x+1.2, 2.5, desc, ha='center', va='center', fontsize=8, color='#424242')

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig2_1_traditional_methods.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig2_1_traditional_methods.png")

def create_ml_workflow():
    """Fig 2.2: Machine Learning-Based Phishing Detection Workflow"""
    fig, ax = plt.subplots(figsize=(14, 7))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 7)
    ax.axis('off')

    ax.text(7, 6.5, 'Fig 2.2: Machine Learning-Based Phishing Detection Workflow',
            ha='center', va='center', fontsize=14, fontweight='bold')

    stages = [
        ('Data\nCollection', '#E3F2FD', '#1565C0', 'Enron\nSpamAssassin\nPhishTank'),
        ('Feature\nExtraction', '#E8F5E9', '#2E7D32', 'Text features\nStructural\nURL analysis'),
        ('Model\nTraining', '#FFF3E0', '#EF6C00', 'TF-IDF + LogReg\nRandom Forest\nDistilBERT + XGBoost'),
        ('Prediction', '#F3E5F5', '#7B1FA2', 'Real-time\nclassification\nConfidence scores'),
        ('Evaluation', '#E0F7FA', '#00695C', 'Accuracy\nPrecision/Recall\nROC-AUC')
    ]

    for i, (name, bg, border, desc) in enumerate(stages):
        x = 0.5 + i * 2.7
        box = FancyBboxPatch((x, 1.5), 2.3, 2.5, boxstyle="round,pad=0.05",
                              facecolor=bg, edgecolor=border, linewidth=2)
        ax.add_patch(box)
        ax.text(x+1.15, 3.5, name, ha='center', va='center', fontsize=11, fontweight='bold')
        ax.text(x+1.15, 2.3, desc, ha='center', va='center', fontsize=8)

        # Arrow to next
        if i < 4:
            ax.annotate('', xy=(x+2.6, 2.75), xytext=(x+2.3, 2.75),
                        arrowprops=dict(arrowstyle='->', color='#424242', lw=2))

    # Feedback loop
    ax.annotate('', xy=(12.5, 4.5), xytext=(12.5, 2),
                arrowprops=dict(arrowstyle='->', color='#C62828', lw=2))
    ax.text(13, 3.2, 'Feedback\nLoop', fontsize=8, color='#C62828', va='center')

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig2_2_ml_workflow.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig2_2_ml_workflow.png")

def create_data_pipeline():
    """Fig 3.1: Data Collection and Preprocessing Pipeline"""
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis('off')

    ax.text(7, 7.5, 'Fig 3.1: Data Collection and Preprocessing Pipeline',
            ha='center', va='center', fontsize=14, fontweight='bold')

    # Data Sources
    sources_box = FancyBboxPatch((0.5, 5), 3, 2, boxstyle="round,pad=0.05",
                                  facecolor='#E3F2FD', edgecolor='#1565C0', linewidth=2)
    ax.add_patch(sources_box)
    ax.text(2, 6.5, 'DATA SOURCES', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(2, 5.7, '• Enron Corpus (700K)\n• SpamAssassin (5K)\n• PhishTank (600K URLs)',
            ha='center', va='center', fontsize=9)

    # Preprocessing
    pre_box = FancyBboxPatch((4.5, 5), 3, 2, boxstyle="round,pad=0.05",
                              facecolor='#E8F5E9', edgecolor='#2E7D32', linewidth=2)
    ax.add_patch(pre_box)
    ax.text(6, 6.5, 'PREPROCESSING', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(6, 5.7, '• HTML cleaning\n• Lowercasing\n• Tokenization (spaCy)\n• Stopword removal',
            ha='center', va='center', fontsize=9)

    # Feature Engineering
    feat_box = FancyBboxPatch((8.5, 5), 3, 2, boxstyle="round,pad=0.05",
                               facecolor='#FFF3E0', edgecolor='#EF6C00', linewidth=2)
    ax.add_patch(feat_box)
    ax.text(10, 6.5, 'FEATURE\nENGINEERING', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(10, 5.7, '• Text: TF-IDF (5,000)\n• BERT embeddings (768)\n• Structural (50+)',
            ha='center', va='center', fontsize=9)

    # Split
    split_box = FancyBboxPatch((0.5, 1.5), 3, 2, boxstyle="round,pad=0.05",
                                facecolor='#F3E5F5', edgecolor='#7B1FA2', linewidth=2)
    ax.add_patch(split_box)
    ax.text(2, 3, 'TRAIN/TEST\nSPLIT 80/20', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(2, 2, '• Training: 12,648\n• Testing: 3,163\n• Stratified sampling',
            ha='center', va='center', fontsize=9)

    # Model Training
    train_box = FancyBboxPatch((4.5, 1.5), 3, 2, boxstyle="round,pad=0.05",
                                facecolor='#E0F7FA', edgecolor='#00695C', linewidth=2)
    ax.add_patch(train_box)
    ax.text(6, 3, 'MODEL\nTRAINING', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(6, 2, '• Logistic Regression\n• Random Forest\n• DistilBERT + XGBoost',
            ha='center', va='center', fontsize=9)

    # Output
    out_box = FancyBboxPatch((8.5, 1.5), 3, 2, boxstyle="round,pad=0.05",
                              facecolor='#ECEFF1', edgecolor='#455A64', linewidth=2)
    ax.add_patch(out_box)
    ax.text(10, 3, 'OUTPUT', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(10, 2, '• Models (.pkl)\n• Metrics (.json)\n• Results (15,811 samples)',
            ha='center', va='center', fontsize=9)

    # Arrows
    arrow_points = [(3.5, 6), (7.5, 6), (11.5, 6), (3.5, 3.5), (7.5, 3.5), (11.5, 3.5)]
    for i in range(0, 6, 2):
        ax.annotate('', xy=arrow_points[i+1], xytext=arrow_points[i],
                    arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig3_1_data_pipeline.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig3_1_data_pipeline.png")

def create_hybrid_model():
    """Fig 3.2: Hybrid Model Architecture (DistilBERT + XGBoost)"""
    fig, ax = plt.subplots(figsize=(14, 9))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 9)
    ax.axis('off')

    ax.text(7, 8.5, 'Fig 3.2: Hybrid Model Architecture (DistilBERT + XGBoost)',
            ha='center', va='center', fontsize=14, fontweight='bold')

    # Input Email
    input_box = FancyBboxPatch((1, 6.5), 4, 1.5, boxstyle="round,pad=0.05",
                                facecolor='#E3F2FD', edgecolor='#1565C0', linewidth=2)
    ax.add_patch(input_box)
    ax.text(3, 7.5, 'INPUT EMAIL', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(3, 6.9, 'Subject + Body + URLs', fontsize=9)

    # DistilBERT Branch
    bert_box = FancyBboxPatch((0.5, 3.5), 4, 2.5, boxstyle="round,pad=0.05",
                               facecolor='#FFF3E0', edgecolor='#EF6C00', linewidth=2)
    ax.add_patch(bert_box)
    ax.text(2.5, 5.5, 'DistilBERT (Text)', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(2.5, 4.8, '• Pre-trained transformer\n• 768-dim embeddings\n• Semantic understanding', fontsize=9)

    # Structural Branch
    struct_box = FancyBboxPatch((5.5, 3.5), 4, 2.5, boxstyle="round,pad=0.05",
                                 facecolor='#F3E5F5', edgecolor='#7B1FA2', linewidth=2)
    ax.add_patch(struct_box)
    ax.text(7.5, 5.5, 'Structural Features', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(7.5, 4.8, '• URL analysis (15)\n• Domain reputation (12)\n• Header analysis (10)\n• Content patterns (8)', fontsize=9)

    # Concatenate
    concat_box = FancyBboxPatch((3, 1.5), 4, 1.5, boxstyle="round,pad=0.05",
                                 facecolor='#FFEBEE', edgecolor='#C62828', linewidth=2)
    ax.add_patch(concat_box)
    ax.text(5, 2.5, 'CONCATENATE (778 features)', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(5, 2, '768 BERT + 10 Structural', fontsize=9)

    # XGBoost
    xgb_box = FancyBboxPatch((3, 0.2), 4, 1, boxstyle="round,pad=0.05",
                              facecolor='#E0F7FA', edgecolor='#00695C', linewidth=2)
    ax.add_patch(xgb_box)
    ax.text(5, 0.7, 'XGBoost Classifier', ha='center', va='center', fontsize=11, fontweight='bold')

    # Output
    output_box = FancyBboxPatch((10, 3.5), 3, 1.5, boxstyle="round,pad=0.05",
                                 facecolor='#ECEFF1', edgecolor='#455A64', linewidth=2)
    ax.add_patch(output_box)
    ax.text(11.5, 4.5, 'OUTPUT', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(11.5, 3.9, 'Phishing: Yes/No\nConfidence: 0-100%', fontsize=9)

    # Arrows
    ax.annotate('', xy=(2.5, 3.5), xytext=(3, 6.5),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))
    ax.annotate('', xy=(7.5, 3.5), xytext=(7, 6.5),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))
    ax.annotate('', xy=(5, 1.5), xytext=(5, 3),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))
    ax.annotate('', xy=(10, 4.5), xytext=(8, 2.5),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=1.5))

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig3_2_hybrid_model.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig3_2_hybrid_model.png")

def create_extension_workflow():
    """Fig 3.3: Browser Extension Workflow"""
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 6)
    ax.axis('off')

    ax.text(7, 5.5, 'Fig 3.3: Browser Extension Workflow',
            ha='center', va='center', fontsize=14, fontweight='bold')

    steps = [
        ('1. Email\nOpened', '#E3F2FD', '#1565C0'),
        ('2. User Clicks\nExtension', '#E8F5E9', '#2E7D32'),
        ('3. Extract\nEmail Data', '#FFF3E0', '#EF6C00'),
        ('4. Send to\nBackend API', '#F3E5F5', '#7B1FA2'),
        ('5. ML\nAnalysis', '#E0F7FA', '#00695C'),
        ('6. Display\nResult', '#ECEFF1', '#455A64')
    ]

    for i, (name, bg, border) in enumerate(steps):
        x = 0.8 + i * 2.2
        box = FancyBboxPatch((x, 1), 1.8, 2.5, boxstyle="round,pad=0.05",
                              facecolor=bg, edgecolor=border, linewidth=2)
        ax.add_patch(box)
        ax.text(x+0.9, 2.25, name, ha='center', va='center', fontsize=10, fontweight='bold')

        if i < 5:
            ax.annotate('', xy=(x+2.1, 2.25), xytext=(x+1.8, 2.25),
                        arrowprops=dict(arrowstyle='->', color='#424242', lw=2))

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig3_3_extension_workflow.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig3_3_extension_workflow.png")

def create_testing_workflow():
    """Fig 3.4: Testing and Evaluation Workflow"""
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 6)
    ax.axis('off')

    ax.text(7, 5.5, 'Fig 3.4: Testing and Evaluation Workflow',
            ha='center', va='center', fontsize=14, fontweight='bold')

    # Test box
    test_box = FancyBboxPatch((1, 1.5), 3, 3, boxstyle="round,pad=0.05",
                                facecolor='#E3F2FD', edgecolor='#1565C0', linewidth=2)
    ax.add_patch(test_box)
    ax.text(2.5, 4, 'TEST SET', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(2.5, 3, '3,163 emails\n• 381 phishing\n• 2,782 legitimate', fontsize=9)

    # Model box
    model_box = FancyBboxPatch((5, 1.5), 3, 3, boxstyle="round,pad=0.05",
                                facecolor='#E8F5E9', edgecolor='#2E7D32', linewidth=2)
    ax.add_patch(model_box)
    ax.text(6.5, 4, 'PREDICTIONS', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(6.5, 3, 'Run model on\ntest set\nGenerate labels', fontsize=9)

    # Metrics box
    metrics_box = FancyBboxPatch((9, 1.5), 4, 3, boxstyle="round,pad=0.05",
                                  facecolor='#FFF3E0', edgecolor='#EF6C00', linewidth=2)
    ax.add_patch(metrics_box)
    ax.text(11, 4, 'EVALUATION METRICS', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(11, 3.2, '• Confusion Matrix\n• ROC Curve\n• Precision-Recall\n• Accuracy, F1, AUC', fontsize=9)

    # Arrows
    ax.annotate('', xy=(5, 3), xytext=(4, 3),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=2))
    ax.annotate('', xy=(9, 3), xytext=(8, 3),
                arrowprops=dict(arrowstyle='->', color='#424242', lw=2))

    plt.tight_layout()
    plt.savefig(str(_DOCS_DIR / 'fig3_4_testing_workflow.png'),
                bbox_inches='tight', facecolor='white')
    plt.close()
    print("Created: fig3_4_testing_workflow.png")

if __name__ == '__main__':
    print("Generating PhishTrace Architecture Diagrams...")
    print("=" * 50)
    create_overall_architecture()
    create_email_interface()
    create_traditional_methods()
    create_ml_workflow()
    create_data_pipeline()
    create_hybrid_model()
    create_extension_workflow()
    create_testing_workflow()
    print("=" * 50)
    print("All diagrams generated successfully!")