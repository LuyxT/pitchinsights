"""
Backup Service Module
=====================
Automatische und manuelle Backups der SQLite-Datenbank.
"""

import os
import shutil
import logging
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from config import SecurityConfig

logger = logging.getLogger("pitchinsights.backup")


class BackupConfig:
    """Backup-Konfiguration."""
    BACKUP_DIR: str = os.environ.get("PITCHINSIGHTS_BACKUP_DIR", "data/backups")
    MAX_BACKUPS: int = int(os.environ.get("PITCHINSIGHTS_MAX_BACKUPS", "10"))
    COMPRESS: bool = True


def ensure_backup_dir() -> Path:
    """Stellt sicher, dass das Backup-Verzeichnis existiert."""
    backup_path = Path(BackupConfig.BACKUP_DIR)
    backup_path.mkdir(parents=True, exist_ok=True)
    return backup_path


def create_backup(description: str = "manual") -> Optional[str]:
    """
    Erstellt ein Backup der Datenbank.
    
    Args:
        description: Beschreibung des Backups (z.B. "manual", "scheduled", "pre-migration")
    
    Returns:
        Pfad zur Backup-Datei oder None bei Fehler
    """
    try:
        db_path = Path(SecurityConfig.DATABASE_PATH)
        if not db_path.exists():
            logger.warning("Datenbank existiert nicht - kein Backup möglich")
            return None
        
        backup_dir = ensure_backup_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Backup-Dateiname
        if BackupConfig.COMPRESS:
            backup_name = f"pitchinsights_{timestamp}_{description}.db.gz"
            backup_path = backup_dir / backup_name
            
            # Komprimiertes Backup erstellen
            with open(db_path, 'rb') as f_in:
                with gzip.open(backup_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            backup_name = f"pitchinsights_{timestamp}_{description}.db"
            backup_path = backup_dir / backup_name
            shutil.copy2(db_path, backup_path)
        
        logger.info(f"Backup erstellt: {backup_name}")
        
        # Alte Backups aufräumen
        cleanup_old_backups()
        
        return str(backup_path)
        
    except Exception as e:
        logger.error(f"Backup-Fehler: {type(e).__name__}: {e}")
        return None


def restore_backup(backup_path: str) -> bool:
    """
    Stellt ein Backup wieder her.
    
    WARNUNG: Überschreibt die aktuelle Datenbank!
    
    Args:
        backup_path: Pfad zur Backup-Datei
    
    Returns:
        True bei Erfolg, False bei Fehler
    """
    try:
        backup_file = Path(backup_path)
        if not backup_file.exists():
            logger.error(f"Backup-Datei nicht gefunden: {backup_path}")
            return False
        
        db_path = Path(SecurityConfig.DATABASE_PATH)
        
        # Aktuelles DB als Sicherung umbenennen
        if db_path.exists():
            temp_backup = db_path.with_suffix('.db.pre-restore')
            shutil.move(db_path, temp_backup)
        
        try:
            if backup_path.endswith('.gz'):
                # Komprimiertes Backup entpacken
                with gzip.open(backup_file, 'rb') as f_in:
                    with open(db_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(backup_file, db_path)
            
            logger.info(f"Backup wiederhergestellt: {backup_path}")
            
            # Alte Sicherung löschen
            if temp_backup.exists():
                temp_backup.unlink()
            
            return True
            
        except Exception as e:
            # Bei Fehler: Ursprüngliche DB wiederherstellen
            if temp_backup.exists():
                shutil.move(temp_backup, db_path)
            raise e
            
    except Exception as e:
        logger.error(f"Restore-Fehler: {type(e).__name__}: {e}")
        return False


def list_backups() -> List[dict]:
    """
    Listet alle verfügbaren Backups.
    
    Returns:
        Liste von Backup-Informationen
    """
    backup_dir = ensure_backup_dir()
    backups = []
    
    for file in sorted(backup_dir.glob("pitchinsights_*.db*"), reverse=True):
        stat = file.stat()
        backups.append({
            "filename": file.name,
            "path": str(file),
            "size": stat.st_size,
            "size_human": format_size(stat.st_size),
            "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "compressed": file.suffix == ".gz"
        })
    
    return backups


def cleanup_old_backups() -> int:
    """
    Löscht alte Backups über dem Limit.
    
    Returns:
        Anzahl gelöschter Backups
    """
    backup_dir = ensure_backup_dir()
    backups = sorted(backup_dir.glob("pitchinsights_*.db*"), reverse=True)
    
    deleted = 0
    for backup in backups[BackupConfig.MAX_BACKUPS:]:
        try:
            backup.unlink()
            logger.info(f"Altes Backup gelöscht: {backup.name}")
            deleted += 1
        except Exception as e:
            logger.warning(f"Konnte Backup nicht löschen: {backup.name}")
    
    return deleted


def format_size(size_bytes: int) -> str:
    """Formatiert Bytes in menschenlesbare Größe."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def get_backup_stats() -> dict:
    """
    Gibt Statistiken über Backups zurück.
    """
    backups = list_backups()
    total_size = sum(b["size"] for b in backups)
    
    return {
        "count": len(backups),
        "total_size": total_size,
        "total_size_human": format_size(total_size),
        "oldest": backups[-1]["created"] if backups else None,
        "newest": backups[0]["created"] if backups else None,
        "max_backups": BackupConfig.MAX_BACKUPS
    }


# ============================================
# Scheduled Backup (für Background Tasks)
# ============================================

async def scheduled_backup():
    """
    Erstellt ein geplantes Backup.
    Kann von einem Scheduler aufgerufen werden.
    """
    return create_backup("scheduled")
